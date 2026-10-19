# Contrato publicado pelos repositórios de infraestrutura (specs 06 e 07). Nada de rede ou banco é
# copiado à mão: se o infra-k8s ou o infra-database não foram aplicados neste workspace, o plan falha
# aqui com ParameterNotFound, apontando exatamente o que falta.
data "aws_ssm_parameter" "vpc_id" {
  name = "/${var.project_name}/${local.env}/vpc_id"
}

data "aws_ssm_parameter" "private_subnet_ids" {
  name = "/${var.project_name}/${local.env}/private_subnet_ids"
}

data "aws_ssm_parameter" "rds_security_group_id" {
  name = "/${var.project_name}/${local.env}/rds_security_group_id"
}

data "aws_ssm_parameter" "db_endpoint" {
  name = "/${var.project_name}/${local.env}/db_endpoint"
}

data "aws_ssm_parameter" "db_port" {
  name = "/${var.project_name}/${local.env}/db_port"
}

data "aws_ssm_parameter" "db_name" {
  name = "/${var.project_name}/${local.env}/db_name"
}

# A conta AWS Academy bloqueia iam:CreateRole: a função usa a LabRole existente. Ela precisa aceitar
# lambda.amazonaws.com na trust policy e ter as permissões de ENI para Lambda em VPC
# (ec2:CreateNetworkInterface, DescribeNetworkInterfaces, DeleteNetworkInterface). Validar na primeira
# sessão: se a trust policy não aceitar, o apply falha com a mensagem do IAM apontando o papel.
data "aws_iam_role" "lab_role" {
  name = "LabRole"
}

locals {
  vpc_id                = data.aws_ssm_parameter.vpc_id.value
  private_subnet_ids    = split(",", data.aws_ssm_parameter.private_subnet_ids.value)
  rds_security_group_id = data.aws_ssm_parameter.rds_security_group_id.value
}
