#!/usr/bin/env bash
# Cria (se não existir) o bucket de state do Terraform: oficina-tfstate-<account-id>.
# Idempotente — usado pela pipeline e pode ser rodado à mão. O ID da conta no nome evita
# colisão no namespace global do S3 e acompanha a reciclagem da conta AWS Academy.
#
# Uso: ./scripts/bootstrap-state-bucket.sh   (com credenciais AWS no ambiente)
# Imprime o nome do bucket em stdout (demais mensagens vão para stderr).
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="oficina-tfstate-${ACCOUNT_ID}"

if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "bucket $BUCKET já existe" >&2
else
  echo "criando $BUCKET" >&2
  # us-east-1 não aceita LocationConstraint.
  aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >&2
fi

# Reaplicados sempre: são idempotentes e corrigem um bucket criado à mão sem eles.
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled >/dev/null
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null

echo "$BUCKET"
