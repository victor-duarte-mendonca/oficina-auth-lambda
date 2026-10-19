# Mesmos workspaces dos demais repositórios. O workspace "default" é inválido de propósito: o plan
# falha com 'Invalid index' em vez de criar a função sem ambiente definido.
locals {
  env = terraform.workspace

  environments = {
    hml  = {}
    prod = {}
  }

  # Valores por ambiente (opcionais): hoje só reserved_concurrency pode ser sobrescrito. Também força o
  # erro acima quando o workspace não é hml/prod.
  config      = local.environments[local.env]
  name_prefix = "${var.project_name}-${local.env}"
}
