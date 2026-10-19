variable "project_name" {
  description = "Prefixo usado no nome dos recursos"
  type        = string
  default     = "oficina"
}

variable "aws_region" {
  description = "Região AWS. Deve coincidir com a região do backend em backend.tf"
  type        = string
  default     = "us-east-1"
}

variable "package_path" {
  description = "JAR com dependências gerado por 'mvn package' (auth-function/target/auth-function.jar)"
  type        = string
  default     = "../auth-function/target/auth-function.jar"
}

variable "memory_size" {
  description = "Memória em MB. Abaixo de 512, a assinatura RSA e o handshake TLS do JDBC dominam a latência"
  type        = number
  default     = 512
}

variable "timeout_seconds" {
  description = "Timeout da função"
  type        = number
  default     = 10
}

variable "reserved_concurrency" {
  description = "Teto de concorrência: protege o db.t4g.micro (~112 conexões) e limita o custo de um loop. Use -1 para não reservar, se a conta Academy recusar"
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "Retenção do log group (sem isto o padrão é 'para sempre')"
  type        = number
  default     = 7
}

variable "db_user" {
  description = "Papel somente-leitura do banco (criado pela migration V6 da aplicação)"
  type        = string
  default     = "oficina_auth_ro"
}

variable "db_password" {
  description = "Senha do papel oficina_auth_ro — TF_VAR_db_password (GitHub Secret LAMBDA_RO_PASSWORD), nunca hardcoded"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_password) >= 16
    error_message = "A senha do papel somente-leitura deve ter ao menos 16 caracteres."
  }
}

variable "jwt_private_key_pem" {
  description = "Chave privada RSA (PKCS#8) que assina o token — a mesma da aplicação. TF_VAR_jwt_private_key_pem (GitHub Secret JWT_PRIVATE_KEY_PEM)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.jwt_private_key_pem) > 0
    error_message = "A chave privada JWT é obrigatória."
  }
}

variable "jwt_issuer" {
  description = "Emissor do token; idêntico ao da aplicação (mp.jwt.verify.issuer)"
  type        = string
  default     = "oficina-api"
}

variable "jwt_ttl_seconds" {
  description = "Validade do token"
  type        = number
  default     = 3600
}
