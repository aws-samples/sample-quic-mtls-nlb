#!/usr/bin/env bash
# Provision a fleet CA using AWS Private Certificate Authority (general-purpose
# mode, RSA-2048 root CA) and issue a server + valid client + one untrusted
# client cert for the mTLS test matrix.
#
# The untrusted client cert is deliberately signed by a throwaway self-signed
# OpenSSL key — the whole point of the negative test case is that the server
# rejects any cert not signed by our fleet CA, so we do NOT want to sign it
# with the real CA. This also keeps the extra cost to zero.
#
# Outputs, all written to certs/:
#   ca.crt              — fleet CA (root) certificate
#   server.crt/.key     — server cert issued by fleet CA (SAN: quic-example.local)
#   client.crt/.key     — valid client cert issued by fleet CA (CN: drone-001)
#   badclient.crt/.key  — untrusted self-signed cert (for negative test)
#
# Also written to certs/:
#   ca.arn              — the AWS Private CA ARN, used by scripts/teardown.sh
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

REGION="${AWS_REGION:-us-west-2}"
SERVER_HOST="${1:-quic-example.local}"
CA_COMMON_NAME="quic-nlb-demo Fleet CA"
SERVER_CERT_VALIDITY_DAYS=30
CLIENT_CERT_VALIDITY_DAYS=30
ROOT_CERT_VALIDITY_YEARS=10

echo "==> Region: $REGION"

# --- 1. Create the Private CA (general-purpose, RSA 2048) ---
if [[ -s ca.arn ]]; then
  CA_ARN="$(cat ca.arn)"
  echo "==> Reusing existing CA: $CA_ARN"
else
  echo "==> Creating AWS Private CA (general-purpose, RSA_2048)..."
  CA_ARN="$(aws acm-pca create-certificate-authority --region "$REGION" \
    --certificate-authority-type ROOT \
    --certificate-authority-configuration '{
      "KeyAlgorithm": "RSA_2048",
      "SigningAlgorithm": "SHA256WITHRSA",
      "Subject": {
        "Country": "US",
        "Organization": "quic-nlb-demo",
        "CommonName": "'"$CA_COMMON_NAME"'"
      }
    }' \
    --tags Key=Project,Value=quic-nlb-blog-demo \
    --query CertificateAuthorityArn --output text)"
  echo "$CA_ARN" > ca.arn
  echo "    ARN: $CA_ARN"
fi

# --- 2. Wait for CA to leave the transient CREATING state ---
# A freshly-created CA sits in CREATING for ~10-30 seconds before transitioning
# to PENDING_CERTIFICATE. If we skip this wait, the next PCA calls fail with
# InvalidStateException.
echo "==> Waiting for CA to leave CREATING state..."
for i in $(seq 1 30); do
  CA_STATUS="$(aws acm-pca describe-certificate-authority --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --query 'CertificateAuthority.Status' --output text)"
  [[ "$CA_STATUS" != "CREATING" ]] && break
  echo "    still CREATING ($i/30)"; sleep 4
done
echo "==> CA status: $CA_STATUS"
if [[ "$CA_STATUS" == "CREATING" ]]; then
  echo "ERROR: CA still in CREATING after 2 minutes. Try re-running the script." >&2
  exit 1
fi

if [[ "$CA_STATUS" == "PENDING_CERTIFICATE" ]]; then
  echo "==> Issuing root certificate for the CA (self-signed via RootCACertificate template)..."
  aws acm-pca get-certificate-authority-csr --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" --output text > root-ca.csr

  ROOT_CERT_ARN="$(aws acm-pca issue-certificate --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --csr "fileb://root-ca.csr" \
    --signing-algorithm SHA256WITHRSA \
    --template-arn arn:aws:acm-pca:::template/RootCACertificate/V1 \
    --validity "Value=$ROOT_CERT_VALIDITY_YEARS,Type=YEARS" \
    --query CertificateArn --output text)"

  echo "==> Waiting for the root certificate to be issued..."
  aws acm-pca wait certificate-issued --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --certificate-arn "$ROOT_CERT_ARN"

  aws acm-pca get-certificate --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --certificate-arn "$ROOT_CERT_ARN" \
    --query Certificate --output text > ca.crt

  echo "==> Importing root certificate into CA (activates it)..."
  aws acm-pca import-certificate-authority-certificate --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --certificate "fileb://ca.crt"

  echo "==> Waiting for CA to become ACTIVE..."
  for i in 1 2 3 4 5 6 7 8 9 10; do
    CA_STATUS="$(aws acm-pca describe-certificate-authority --region "$REGION" \
      --certificate-authority-arn "$CA_ARN" \
      --query 'CertificateAuthority.Status' --output text)"
    [[ "$CA_STATUS" == "ACTIVE" ]] && break
    echo "    still $CA_STATUS ($i/10)"; sleep 6
  done
  if [[ "$CA_STATUS" != "ACTIVE" ]]; then
    echo "ERROR: CA did not reach ACTIVE state" >&2
    exit 1
  fi
fi

# Make sure we have the current CA cert on disk even on a re-run
aws acm-pca get-certificate-authority-certificate --region "$REGION" \
  --certificate-authority-arn "$CA_ARN" \
  --query Certificate --output text > ca.crt

# --- 3. Issue an end-entity cert given a locally-generated key + CSR ---
issue_cert () {
  local name="$1"       # server | client
  local cn="$2"         # CommonName
  local san_hint="$3"   # DNS:foo,DNS:bar   (used only for server)
  local days="$4"

  openssl genrsa -out "${name}.key" 2048 2>/dev/null

  # CSR with SAN embedded via -addext (server) or no SAN (client)
  if [[ -n "$san_hint" ]]; then
    openssl req -new -key "${name}.key" -out "${name}.csr" \
      -subj "/CN=${cn}" -addext "subjectAltName=${san_hint}"
    # PCA respects the CSR's SubjectAlternativeName only when using the
    # APICSRPassthrough template
    local template="arn:aws:acm-pca:::template/EndEntityCertificate_APICSRPassthrough/V1"
  else
    openssl req -new -key "${name}.key" -out "${name}.csr" -subj "/CN=${cn}/O=fleet-demo"
    local template="arn:aws:acm-pca:::template/EndEntityCertificate/V1"
  fi

  local cert_arn
  cert_arn="$(aws acm-pca issue-certificate --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --csr "fileb://${name}.csr" \
    --signing-algorithm SHA256WITHRSA \
    --template-arn "$template" \
    --validity "Value=${days},Type=DAYS" \
    --query CertificateArn --output text)"

  aws acm-pca wait certificate-issued --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --certificate-arn "$cert_arn"

  aws acm-pca get-certificate --region "$REGION" \
    --certificate-authority-arn "$CA_ARN" \
    --certificate-arn "$cert_arn" \
    --query Certificate --output text > "${name}.crt"
}

echo "==> Issuing server certificate (CN=${SERVER_HOST})..."
issue_cert server "$SERVER_HOST" "DNS:${SERVER_HOST},DNS:localhost,IP:127.0.0.1" "$SERVER_CERT_VALIDITY_DAYS"

echo "==> Issuing valid client certificate (CN=drone-001)..."
issue_cert client "drone-001" "" "$CLIENT_CERT_VALIDITY_DAYS"

# --- 4. Untrusted (bad) client cert — self-signed via OpenSSL ---
# Deliberately NOT signed by the fleet CA. This exercises the "cert from an
# unrelated authority" case in the mTLS test matrix.
echo "==> Generating untrusted self-signed client cert (for the negative test case)..."
openssl genrsa -out badclient.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key badclient.key -sha256 -days 15 \
  -subj "/CN=untrusted-device" -out badclient.crt

# --- 5. Summary ---
echo
echo "==> Done. Certs written to: $CERT_DIR"
ls -1 "$CERT_DIR"
echo
echo "Fingerprints:"
openssl x509 -in ca.crt         -noout -subject -fingerprint -sha256
openssl x509 -in server.crt     -noout -subject -issuer -fingerprint -sha256
openssl x509 -in client.crt     -noout -subject -issuer -fingerprint -sha256
openssl x509 -in badclient.crt  -noout -subject -issuer -fingerprint -sha256
echo
echo "CA ARN (saved to certs/ca.arn for teardown.sh): $CA_ARN"
