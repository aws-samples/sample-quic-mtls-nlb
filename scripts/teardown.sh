#!/usr/bin/env bash
# Tear down every AWS resource created for the mTLS-over-QUIC-on-NLB demo.
# Run this from a shell that has active AWS credentials for the account
# where the demo was deployed (Admin or equivalent permissions required).
#
# Order matters:
#   1. Delete the K8s Service so the LBC deletes the NLB + target group first.
#      If we skip this and delete the cluster, the NLB is orphaned and CFN
#      stack deletion for the OIDC/IRSA service accounts will fail.
#   2. Uninstall the AWS Load Balancer Controller helm release.
#   3. Delete the eksctl-managed IAM service account (removes CFN stack).
#   4. Delete the ECR repository (with --force to nuke images).
#   5. Delete the EKS cluster (eksctl removes the nodegroup + CFN stacks).
#   6. Detach + delete the AWSLoadBalancerControllerIAMPolicy.
#   7. Disable + schedule the AWS Private CA for deletion (independent of EKS,
#      but done last so the CA is still available if you need to re-issue
#      certs during teardown troubleshooting).
set -euo pipefail

CLUSTER=quic-nlb-demo
REGION=us-west-2
NAMESPACE=quic-example
ECR_REPO=quic-nlb-demo
POLICY_NAME=AWSLoadBalancerControllerIAMPolicy
CA_ARN_FILE="$(cd "$(dirname "$0")/.." && pwd)/certs/ca.arn"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

echo "==> Deleting Kubernetes Service (lets LBC clean up the NLB first)"
kubectl -n "$NAMESPACE" delete svc quic-service --ignore-not-found=true
# Give the LBC time to reconcile the deletion (it removes NLB + target group)
for i in $(seq 1 24); do
  if ! aws elbv2 describe-load-balancers --region "$REGION" --names "$CLUSTER" >/dev/null 2>&1; then
    echo "    NLB deleted"
    break
  fi
  echo "    waiting for NLB deletion... ($i)"
  sleep 10
done

echo "==> Deleting demo namespace"
kubectl delete ns "$NAMESPACE" --ignore-not-found=true --wait=false

echo "==> Uninstalling AWS Load Balancer Controller helm release"
helm uninstall aws-load-balancer-controller -n kube-system 2>/dev/null || true

echo "==> Deleting IAM service account (removes IRSA role + CFN stack)"
eksctl delete iamserviceaccount \
  --cluster "$CLUSTER" --region "$REGION" \
  --namespace kube-system --name aws-load-balancer-controller 2>/dev/null || true

echo "==> Deleting ECR repository (with images)"
aws ecr delete-repository --repository-name "$ECR_REPO" --region "$REGION" --force 2>/dev/null || true

echo "==> Deleting EKS cluster (this removes the nodegroup + control plane)"
eksctl delete cluster --name "$CLUSTER" --region "$REGION" --wait

echo "==> Detaching and deleting IAM policy $POLICY_NAME"
POLICY_ARN="arn:aws:iam::${ACCOUNT}:policy/${POLICY_NAME}"
for role in $(aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --query 'PolicyRoles[*].RoleName' --output text 2>/dev/null); do
  aws iam detach-role-policy --role-name "$role" --policy-arn "$POLICY_ARN" 2>/dev/null || true
done
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null || true

echo "==> Disabling and deleting the AWS Private CA"
# The CA ARN was written to certs/ca.arn by scripts/gen-certs.sh
if [[ -s "$CA_ARN_FILE" ]]; then
  CA_ARN="$(cat "$CA_ARN_FILE")"
  CA_STATUS="$(aws acm-pca describe-certificate-authority --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --query 'CertificateAuthority.Status' --output text 2>/dev/null || echo MISSING)"
  case "$CA_STATUS" in
    ACTIVE)
      echo "    Disabling CA..."
      aws acm-pca update-certificate-authority --region "$REGION" \
        --certificate-authority-arn "$CA_ARN" --status DISABLED
      ;;
    DISABLED|PENDING_CERTIFICATE|EXPIRED|FAILED)
      echo "    CA is $CA_STATUS, proceeding to schedule deletion"
      ;;
    DELETED)
      echo "    CA already deleted"
      ;;
    MISSING)
      echo "    CA not found (already gone?), skipping"
      ;;
  esac

  if [[ "$CA_STATUS" != "DELETED" && "$CA_STATUS" != "MISSING" ]]; then
    # Minimum permanent-deletion window is 7 days. Within that window you can
    # call restore-certificate-authority to recover it.
    echo "    Scheduling permanent deletion (7-day recovery window)..."
    aws acm-pca delete-certificate-authority --region "$REGION" \
      --certificate-authority-arn "$CA_ARN" \
      --permanent-deletion-time-in-days 7 || true
    echo "    CA scheduled for deletion. To restore within 7 days:"
    echo "      aws acm-pca restore-certificate-authority --region $REGION \\"
    echo "        --certificate-authority-arn $CA_ARN"
  fi
  rm -f "$CA_ARN_FILE"
else
  echo "    No certs/ca.arn file found — either you didn't run gen-certs.sh"
  echo "    or the CA was already torn down. Skipping."
fi

echo "==> Done. Verify with:"
echo "    aws eks list-clusters --region $REGION"
echo "    aws elbv2 describe-load-balancers --region $REGION"
echo "    aws ecr describe-repositories --region $REGION"
echo "    aws acm-pca list-certificate-authorities --region $REGION"
