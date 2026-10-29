# SG próprio da função. Sem NAT Gateway (US$ 32/mês) e sem saída para a internet: o Lambda só fala com o
# RDS, que está na mesma VPC.
resource "aws_security_group" "lambda" {
  name_prefix = "${local.name_prefix}-auth-lambda-"
  description = "Lambda de autenticacao: so alcanca o RDS na 5432"
  vpc_id      = local.vpc_id

  tags = { Name = "${local.name_prefix}-auth-lambda-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# Única saída permitida: PostgreSQL no SG do RDS. A resolução de DNS do endpoint do RDS usa o resolver
# da VPC, que não passa por security group.
resource "aws_vpc_security_group_egress_rule" "to_rds" {
  security_group_id            = aws_security_group.lambda.id
  description                  = "PostgreSQL no RDS"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = local.rds_security_group_id
}

# A regra de ENTRADA no RDS mora aqui, e não no oficina-infra-database: o SG do Lambda só existe depois
# do RDS (spec 07 §2). O infra-database publica rds_security_group_id no SSM justamente para isto.
resource "aws_vpc_security_group_ingress_rule" "rds_from_auth_lambda" {
  security_group_id            = local.rds_security_group_id
  description                  = "PostgreSQL do Lambda de autenticacao"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.lambda.id
}
