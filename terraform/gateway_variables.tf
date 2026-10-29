variable "authorizer_package_path" {
  description = "JAR do authorizer gerado por 'mvn package' (authorizer-function/target/authorizer-function.jar)"
  type        = string
  default     = "../authorizer-function/target/authorizer-function.jar"
}

variable "authorizer_memory_size" {
  description = "Memória do authorizer em MB (CPU proporcional: a verificação RSA é o custo dominante)"
  type        = number
  default     = 512
}

variable "authorizer_timeout_seconds" {
  description = "Timeout do authorizer: ele só verifica uma assinatura, sem rede nem banco"
  type        = number
  default     = 5
}

variable "gateway_key" {
  description = "Valor de X-Gateway-Key injetado pelo gateway e exigido pela aplicação em /admin e /me — TF_VAR_gateway_key (GitHub Secret APP_GATEWAY_KEY), o MESMO da aplicação"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.gateway_key) >= 16
    error_message = "A chave do gateway deve ter ao menos 16 caracteres."
  }
}

variable "cors_allow_origins" {
  description = "Origens permitidas no CORS do gateway (a origem do front). Com o gateway na frente, o CORS da aplicação só vale para acesso direto em desenvolvimento"
  type        = list(string)
  default     = ["http://localhost:3000"]
}

variable "throttle_rate_limit" {
  description = "Requisições por segundo, padrão da stage"
  type        = number
  default     = 50
}

variable "throttle_burst_limit" {
  description = "Rajada, padrão da stage"
  type        = number
  default     = 100
}

variable "token_route_rate_limit" {
  description = "Requisições por segundo em POST /auth/token: a defesa primária contra enumeração de CPF"
  type        = number
  default     = 10
}

variable "token_route_burst_limit" {
  description = "Rajada em POST /auth/token"
  type        = number
  default     = 20
}
