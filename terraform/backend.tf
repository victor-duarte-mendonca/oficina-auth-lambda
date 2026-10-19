# State remoto em S3, um por workspace (hml/prod):
#   s3://<bucket>/oficina/auth-lambda/<workspace>/terraform.tfstate
#
# Mesmo bucket dos demais repositórios (oficina-tfstate-<account-id>), informado em init:
#   terraform init -backend-config="bucket=$(bash ../scripts/bootstrap-state-bucket.sh)"
terraform {
  backend "s3" {
    key                  = "terraform.tfstate"
    workspace_key_prefix = "oficina/auth-lambda"
    region               = "us-east-1"
    use_lockfile         = true
    encrypt              = true
  }
}
