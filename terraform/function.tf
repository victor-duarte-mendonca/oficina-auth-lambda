# Log group explícito, criado ANTES da função: sem ele o Lambda cria o grupo sozinho, com retenção
# "para sempre" (CloudWatch cobra US$ 0,03/GB-mês retido).
resource "aws_cloudwatch_log_group" "auth" {
  name              = "/aws/lambda/${local.name_prefix}-auth-token"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "auth" {
  function_name = "${local.name_prefix}-auth-token"
  description   = "Autenticacao por CPF: POST /auth/token -> JWT RS256 de papel CLIENT"
  role          = data.aws_iam_role.lab_role.arn

  runtime = "java21"
  handler = "br.com.oficina.auth.infrastructure.AuthHandler::handleRequest"
  # arm64: ~20% mais barato que x86_64, e o JAR é independente de plataforma.
  architectures = ["arm64"]

  filename         = var.package_path
  source_code_hash = filebase64sha256(var.package_path)

  memory_size = var.memory_size
  timeout     = var.timeout_seconds

  # SnapStart só vale em versão publicada (nunca em $LATEST): cada apply com código novo publica uma
  # versão, e o alias abaixo aponta para ela.
  publish = true
  snap_start {
    apply_on = "PublishedVersions"
  }

  # Override por ambiente em locals.tf (chave reserved_concurrency); senão, o valor da variável.
  reserved_concurrent_executions = lookup(local.config, "reserved_concurrency", var.reserved_concurrency)

  vpc_config {
    subnet_ids         = local.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Segredos em variáveis de ambiente (spec 02 §4): sem NAT, Secrets Manager/SSM em runtime exigiriam
  # VPC endpoints pagos. Criptografadas em repouso pela chave gerenciada aws/lambda.
  environment {
    variables = {
      DB_HOST             = data.aws_ssm_parameter.db_endpoint.value
      DB_PORT             = data.aws_ssm_parameter.db_port.value
      DB_NAME             = data.aws_ssm_parameter.db_name.value
      DB_USER             = var.db_user
      DB_PASSWORD         = var.db_password
      JWT_PRIVATE_KEY_PEM = var.jwt_private_key_pem
      JWT_ISSUER          = var.jwt_issuer
      JWT_TTL_SECONDS     = tostring(var.jwt_ttl_seconds)
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.auth.name
  }

  # A função só abre conexão ao atender; mas o RDS precisa aceitar o SG antes do primeiro uso.
  depends_on = [
    aws_vpc_security_group_ingress_rule.rds_from_auth_lambda,
    aws_vpc_security_group_egress_rule.to_rds,
  ]
}

# Alias estável que o API Gateway (E6) invoca. É o alias que aponta para a versão publicada com SnapStart.
resource "aws_lambda_alias" "live" {
  name             = "live"
  description      = "Versao publicada com SnapStart"
  function_name    = aws_lambda_function.auth.function_name
  function_version = aws_lambda_function.auth.version
}

# Invocação síncrona via gateway não retenta, mas isto fecha o caso de invocação assíncrona acidental.
resource "aws_lambda_function_event_invoke_config" "auth" {
  function_name          = aws_lambda_function.auth.function_name
  qualifier              = aws_lambda_alias.live.name
  maximum_retry_attempts = 0
}
