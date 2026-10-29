# E7 (spec 05 §3): logs do gateway e dos dois Lambdas -> New Relic.
#
# Lambda em VPC sem NAT não tem internet: a única saída é o CloudWatch, e este forwarder (FORA da VPC)
# recebe os logs por assinatura e os envia à Log API. Não usa o newrelic-log-ingestion do SAR porque o
# CloudFormation dele cria IAM role, bloqueado no AWS Academy; usa a LabRole como as demais funções.
#
# Liga sozinho: só existe se o oficina-infra-k8s publicou a licença em /oficina/<env>/newrelic_license_key
# (secret NEW_RELIC_LICENSE_KEY do environment dele). Sem licença, nada é criado e o apply segue normal.
data "aws_ssm_parameters_by_path" "shared" {
  path = "/${var.project_name}/${local.env}"
}

locals {
  newrelic_license_ssm_name   = "/${var.project_name}/${local.env}/newrelic_license_key"
  newrelic_forwarder_enabled  = contains(data.aws_ssm_parameters_by_path.shared.names, local.newrelic_license_ssm_name)
  newrelic_forwarder_function = "${local.name_prefix}-newrelic-logs"

  # Grupos de log encaminhados: access log do gateway e logs JSON dos dois Lambdas.
  newrelic_log_sources = local.newrelic_forwarder_enabled ? {
    gateway    = aws_cloudwatch_log_group.gateway.name
    auth       = aws_cloudwatch_log_group.auth.name
    authorizer = aws_cloudwatch_log_group.authorizer.name
  } : {}
}

data "aws_caller_identity" "current" {}

data "archive_file" "log_forwarder" {
  type        = "zip"
  source_dir  = "${path.module}/../log-forwarder"
  output_path = "${path.module}/.build/log-forwarder.zip"
  excludes    = ["forwarder.test.mjs"]
}

resource "aws_cloudwatch_log_group" "log_forwarder" {
  count = local.newrelic_forwarder_enabled ? 1 : 0

  name              = "/aws/lambda/${local.newrelic_forwarder_function}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "log_forwarder" {
  count = local.newrelic_forwarder_enabled ? 1 : 0

  function_name = local.newrelic_forwarder_function
  description   = "Encaminha logs do CloudWatch (gateway e Lambdas) para o New Relic"
  role          = data.aws_iam_role.lab_role.arn

  runtime       = "nodejs20.x"
  handler       = "index.handler"
  architectures = ["arm64"]
  memory_size   = 128
  timeout       = 30

  filename         = data.archive_file.log_forwarder.output_path
  source_code_hash = data.archive_file.log_forwarder.output_base64sha256

  # Fora da VPC de propósito: precisa de internet para chegar à Log API.
  environment {
    variables = {
      LICENSE_SSM_NAME = local.newrelic_license_ssm_name
      SERVICE_ENV      = local.env
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.log_forwarder[0].name
  }
}

resource "aws_lambda_permission" "logs_invoke_forwarder" {
  for_each = local.newrelic_log_sources

  statement_id  = "AllowCloudWatchLogs-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_forwarder[0].function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${each.value}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "newrelic" {
  for_each = local.newrelic_log_sources

  name            = "${local.name_prefix}-newrelic-${each.key}"
  log_group_name  = each.value
  filter_pattern  = ""
  destination_arn = aws_lambda_function.log_forwarder[0].arn

  depends_on = [aws_lambda_permission.logs_invoke_forwarder]
}
