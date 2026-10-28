# Lambda authorizer (spec 03 §4). Roda FORA da VPC, de propósito: só verifica assinatura e validade com a
# chave pública, então não precisa de ENI, não paga cold start de VPC em cada requisição não cacheada e
# não tem como alcançar o banco. Não recebe nenhuma variável de rede nem de banco — essa ausência é o
# controle que o mantém sem acesso ao RDS.

# A chave pública é DERIVADA da privada que já temos (a mesma da aplicação): nada a copiar e nenhum risco
# de as duas metades saírem de sincronia. Só a pública chega ao authorizer.
data "tls_public_key" "jwt" {
  private_key_pem = var.jwt_private_key_pem
}

resource "aws_cloudwatch_log_group" "authorizer" {
  name              = "/aws/lambda/${local.name_prefix}-authorizer"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "authorizer" {
  function_name = "${local.name_prefix}-authorizer"
  description   = "Authorizer do API Gateway: valida o JWT (RS256) antes de a requisicao chegar ao cluster"
  role          = data.aws_iam_role.lab_role.arn

  runtime       = "java21"
  handler       = "br.com.oficina.authorizer.infrastructure.AuthorizerHandler::handleRequest"
  architectures = ["arm64"]

  filename         = var.authorizer_package_path
  source_code_hash = filebase64sha256(var.authorizer_package_path)

  memory_size = var.authorizer_memory_size
  timeout     = var.authorizer_timeout_seconds

  # SnapStart só vale em versão publicada; o alias abaixo aponta para ela.
  publish = true
  snap_start {
    apply_on = "PublishedVersions"
  }

  # SEM vpc_config (spec 03 §4): é o que o diferencia da função de autenticação.

  environment {
    variables = {
      JWT_PUBLIC_KEY_PEM = data.tls_public_key.jwt.public_key_pem
      JWT_ISSUER         = var.jwt_issuer
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.authorizer.name
  }
}

resource "aws_lambda_alias" "authorizer_live" {
  name             = "live"
  description      = "Versao publicada com SnapStart"
  function_name    = aws_lambda_function.authorizer.function_name
  function_version = aws_lambda_function.authorizer.version
}

# Autorizador do tipo REQUEST com resposta simples. O cache de 300 s é por valor do header Authorization:
# uma demonstração inteira gera dezenas de invocações. Limitação conhecida: um token pode continuar aceito
# por até 300 s depois do exp; a aplicação revalida o JWT por conta própria, então a janela não abre acesso.
resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id                            = aws_apigatewayv2_api.main.id
  name                              = "${local.name_prefix}-jwt"
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_alias.authorizer_live.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  identity_sources                  = ["$request.header.Authorization"]
  authorizer_result_ttl_in_seconds  = 300
}

resource "aws_lambda_permission" "gateway_invokes_authorizer" {
  statement_id  = "AllowApiGatewayInvokeAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  qualifier     = aws_lambda_alias.authorizer_live.name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.jwt.id}"
}
