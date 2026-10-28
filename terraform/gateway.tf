# API Gateway HTTP API (spec 03 §2): sem custo por hora (US$ 1,00 por milhão de requisições), uma API por
# ambiente (oficina-hml, oficina-prod), stage $default com auto-deploy.

# EIP do k3s, publicado pelo oficina-infra-k8s: destino da integração HTTP_PROXY.
data "aws_ssm_parameter" "k3s_eip" {
  name = "/${var.project_name}/${local.env}/k3s_eip"
}

resource "aws_apigatewayv2_api" "main" {
  name          = local.name_prefix
  description   = "Gateway da Oficina (${local.env}): autenticacao por CPF, rotas protegidas e roteamento"
  protocol_type = "HTTP"

  # Com o gateway na frente, o CORS da aplicação passa a ser irrelevante para o tráfego externo.
  cors_configuration {
    allow_origins = var.cors_allow_origins
    allow_headers = ["authorization", "content-type"]
    allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    max_age       = 3600
  }
}

# Access log em JSON: é a fonte da latência de API medida no perímetro (R7). Nunca registra o header
# Authorization nem o corpo. authorizerError preenchido com integrationLatency vazio prova que a requisição
# foi barrada no gateway e não chegou ao cluster.
resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/apigateway/${local.name_prefix}"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = var.throttle_rate_limit
    throttling_burst_limit = var.throttle_burst_limit
  }

  # POST /auth/token: a defesa primária contra enumeração de CPF.
  route_settings {
    route_key              = aws_apigatewayv2_route.token.route_key
    throttling_rate_limit  = var.token_route_rate_limit
    throttling_burst_limit = var.token_route_burst_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.gateway.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      requestTime        = "$context.requestTime"
      httpMethod         = "$context.httpMethod"
      routeKey           = "$context.routeKey"
      path               = "$context.path"
      status             = "$context.status"
      responseLength     = "$context.responseLength"
      responseLatency    = "$context.responseLatency"
      integrationLatency = "$context.integration.latency"
      integrationStatus  = "$context.integration.status"
      integrationError   = "$context.integration.error"
      authorizerError    = "$context.authorizer.error"
      authorizerRole     = "$context.authorizer.role"
      sourceIp           = "$context.identity.sourceIp"
      userAgent          = "$context.identity.userAgent"
    })
  }
}
