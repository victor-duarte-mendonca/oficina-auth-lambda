# Contrato publicado para quem consome o gateway (smoke tests, documentação, front). Parâmetro standard:
# gratuito, e a URL não é segredo.
resource "aws_ssm_parameter" "api_gateway_url" {
  name  = "/${var.project_name}/${local.env}/api_gateway_url"
  type  = "String"
  value = aws_apigatewayv2_api.main.api_endpoint
}
