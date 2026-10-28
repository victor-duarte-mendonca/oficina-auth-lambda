output "function_name" {
  description = "Nome da função de autenticação"
  value       = aws_lambda_function.auth.function_name
}

output "alias_name" {
  description = "Alias com SnapStart; invocar sempre por ele (função:alias)"
  value       = aws_lambda_alias.live.name
}

output "alias_arn" {
  description = "ARN do alias (a integração do API Gateway, na E6, usa o invoke_arn)"
  value       = aws_lambda_alias.live.arn
}

output "alias_invoke_arn" {
  description = "ARN de invocação do alias, para a integração AWS_PROXY do API Gateway"
  value       = aws_lambda_alias.live.invoke_arn
}

output "lambda_security_group_id" {
  description = "SG da função"
  value       = aws_security_group.lambda.id
}

output "log_group_name" {
  description = "Log group (retenção definida)"
  value       = aws_cloudwatch_log_group.auth.name
}

output "api_endpoint" {
  description = "URL base do API Gateway (também publicada em SSM /oficina/<env>/api_gateway_url)"
  value       = aws_apigatewayv2_api.main.api_endpoint
}

output "api_id" {
  description = "Id da API (HTTP)"
  value       = aws_apigatewayv2_api.main.id
}

output "gateway_log_group_name" {
  description = "Log group do access log do gateway"
  value       = aws_cloudwatch_log_group.gateway.name
}

output "authorizer_function_name" {
  description = "Nome da função do authorizer"
  value       = aws_lambda_function.authorizer.function_name
}
