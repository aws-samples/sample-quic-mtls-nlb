#!/usr/bin/env bash
# Install AWS Load Balancer Controller via Helm with IRSA.
# Uses the IAM policy shipped in the controller's GitHub main branch.
set -euo pipefail

CLUSTER=quic-nlb-demo
REGION=us-west-2
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
POLICY_NAME=AWSLoadBalancerControllerIAMPolicy
POLICY_ARN="arn:aws:iam::${ACCOUNT}:policy/${POLICY_NAME}"
CHART_VERSION="${CHART_VERSION:-3.5.0}"  # v3.5.0 chart -> controller v3.5.0 (QUIC support)

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Fetching IAM policy for AWS Load Balancer Controller"
curl -fsSL -o "$TMPDIR/iam_policy.json" \
  https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json

if ! aws iam get-policy --policy-arn "$POLICY_ARN" >/dev/null 2>&1; then
  echo "==> Creating IAM policy $POLICY_NAME"
  aws iam create-policy --policy-name "$POLICY_NAME" \
    --policy-document "file://$TMPDIR/iam_policy.json" >/dev/null
else
  echo "==> IAM policy $POLICY_NAME already exists"
fi

echo "==> Creating IRSA service account kube-system/aws-load-balancer-controller"
eksctl create iamserviceaccount \
  --cluster="$CLUSTER" --region="$REGION" \
  --namespace=kube-system --name=aws-load-balancer-controller \
  --attach-policy-arn="$POLICY_ARN" \
  --override-existing-serviceaccounts \
  --approve

echo "==> Adding Helm repo"
helm repo add eks https://aws.github.io/eks-charts >/dev/null 2>&1 || true
helm repo update eks >/dev/null

echo "==> Installing controller chart version ${CHART_VERSION}"
VPC_ID="$(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
  --query 'cluster.resourcesVpcConfig.vpcId' --output text)"

helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --version "$CHART_VERSION" \
  --set clusterName="$CLUSTER" \
  --set region="$REGION" \
  --set vpcId="$VPC_ID" \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller

kubectl -n kube-system rollout status deploy/aws-load-balancer-controller --timeout=180s
kubectl -n kube-system get pods -l app.kubernetes.io/name=aws-load-balancer-controller -o wide
