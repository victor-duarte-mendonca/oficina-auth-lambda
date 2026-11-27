# Rotas (spec 03 §3). Só estas existem: /q/metrics, /q/health/live, /swagger-ui e /openapi NÃO são expostas
# de propósito (superfície interna; quem precisa alcança pelo cluster).

# --- sem autorização ---

# É o endpoint que emite o token: não pode exigir um.
resource "aws_apigatewayv2_route" "token" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /auth/token"
  target    = "integrations/${aws_apigatewayv2_integration.auth_token.id}"
}

# Login de funcionário: já protegido por senha na aplicação.
resource "aws_apigatewayv2_route" "login" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /auth/login"
  target    = "integrations/${aws_apigatewayv2_integration.app["login"].id}"
}

# Usado pelo monitor de uptime.
resource "aws_apigatewayv2_route" "health" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.app["health"].id}"
}

# Acompanhamento por token de uso único da OS.
resource "aws_apigatewayv2_route" "public" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /public/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.app["public"].id}"
}

# --- protegidas pelo authorizer (spec 03 §4) ---

resource "aws_apigatewayv2_route" "admin" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "ANY /admin/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.app["admin"].id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

# Rotas do cliente autenticado por CPF (spec 04).
resource "aws_apigatewayv2_route" "me" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "ANY /me/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.app["me"].id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

# Sétima rota, além das seis da spec: GET /me (o perfil do cliente) não casa com /me/{proxy+}.
resource "aws_apigatewayv2_route" "me_root" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /me"
  target             = "integrations/${aws_apigatewayv2_integration.app["me_root"].id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

# --- Fase 4 (spec 12 §5): sem authorizer JWT ---

# Decisao do orcamento (aprovar/recusar) pelo link do e-mail: a autenticacao e o codigo de uso unico do corpo.
resource "aws_apigatewayv2_route" "public_decision" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /public/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.app["public_decision"].id}"
}

# Webhook da Stripe: a autenticacao e a assinatura (Stripe-Signature, validada pelo Billing). Passa pelo gateway para
# herdar o X-Gateway-Key e o throttling; o corpo e limitado pelo proprio Billing (HTTP API nao limita tamanho).
resource "aws_apigatewayv2_route" "stripe_webhook" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /webhooks/stripe"
  target    = "integrations/${aws_apigatewayv2_integration.app["stripe_webhook"].id}"
}
