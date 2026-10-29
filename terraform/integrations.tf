# Integração com a função de autenticação: AWS_PROXY no ALIAS (onde o SnapStart vale).
resource "aws_apigatewayv2_integration" "auth_token" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_alias.live.invoke_arn
  payload_format_version = "2.0"
  # Um pouco acima do timeout da função (10 s): o erro do Lambda chega ao cliente em vez de um 504 do gateway.
  timeout_milliseconds = 12000
}

resource "aws_lambda_permission" "gateway_invokes_auth" {
  statement_id  = "AllowApiGatewayInvokeAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auth.function_name
  qualifier     = aws_lambda_alias.live.name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/POST/auth/token"
}

# Integrações HTTP_PROXY com a aplicação no k3s. Os prefixos espelham os @Path que a aplicação já expõe
# (/admin/*, /public/*, /auth/login) — nenhuma rota da aplicação muda de endereço por causa do gateway.
#
# Caminho gateway -> cluster em HTTP simples: limitação ASSUMIDA, não esquecimento. Sem domínio não há
# certificado válido, e certificado autoassinado exigiria insecureSkipVerify, que é pior que não ter TLS
# porque aparenta proteção. O caminho de produção é domínio + ACM no gateway e cert-manager no Traefik.
locals {
  eip = data.aws_ssm_parameter.k3s_eip.value

  app_integrations = {
    login = { method = "POST", upstream = "/auth/login" }
    admin = { method = "ANY", upstream = "/admin/{proxy}" }
    me    = { method = "ANY", upstream = "/me/{proxy}" }
    # GET /me (o perfil do cliente) NÃO casa com /me/{proxy+}: o greedy exige ao menos um segmento.
    me_root = { method = "GET", upstream = "/me" }
    health  = { method = "GET", upstream = "/q/health/ready" }
    public  = { method = "GET", upstream = "/public/{proxy}" }
  }
}

resource "aws_apigatewayv2_integration" "app" {
  for_each = local.app_integrations

  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "HTTP_PROXY"
  integration_method     = each.value.method
  integration_uri        = "http://${local.eip}${each.value.upstream}"
  connection_type        = "INTERNET"
  payload_format_version = "1.0"
  timeout_milliseconds   = 10000

  # O gateway injeta X-Gateway-Key; a aplicação rejeita com 403 qualquer requisição autenticada a /admin ou
  # /me sem o valor correto. Protege contra quem descubra o EIP e esteja numa faixa da AWS. O header do
  # cliente é sobrescrito: ele não pode forjar nem omitir a chave.
  # X-Correlation-Id = requestId do gateway (E7): é o id que liga o access log do gateway aos logs e traces da
  # aplicação. Sobrescrito: o cliente não forja o id. O requestId termina em "=" (a aplicação aceita).
  request_parameters = {
    "overwrite:header.X-Gateway-Key"    = var.gateway_key
    "overwrite:header.X-Correlation-Id" = "$context.requestId"
  }
}
