# oficina-auth-lambda

Função serverless de autenticação por CPF (AWS Lambda, **Java 21 + SnapStart**) e, na etapa E6, o API
Gateway HTTP API com o Lambda authorizer — Tech Challenge FIAP, Fase 3.

Repositórios irmãos: [oficina-app](https://github.com/victor-duarte-mendonca/oficina-app),
[oficina-infra-k8s](https://github.com/victor-duarte-mendonca/oficina-infra-k8s),
[oficina-infra-database](https://github.com/victor-duarte-mendonca/oficina-infra-database).

## O que a função faz

`POST /auth/token` com `{"cpf": "529.982.247-25"}` (com ou sem máscara) devolve um JWT que a aplicação
aceita nas rotas `/me/*`:

| Status | Corpo | Quando |
|---|---|---|
| 200 | `{"access_token","token_type":"Bearer","expires_in":3600,"client":{"id","name"}}` | CPF válido, cliente existe e está `ACTIVE` |
| 400 | `{"error":"invalid_request","message":"CPF inválido"}` | CPF ausente, malformado, dígito verificador errado ou sequência repetida |
| 401 | `{"error":"unauthorized","message":"Não foi possível autenticar com os dados informados"}` | Cliente inexistente **ou** `INACTIVE` **ou** `BLOCKED` |
| 500 | `{"error":"internal_error","correlationId":"..."}` | Falha de banco ou de assinatura |

**401 idêntico para os três casos** (byte a byte): o CPF é o único fator, e responder 404 para
inexistente transformaria o endpoint num validador de "este CPF é cliente da oficina?". O motivo
(`not_found`/`inactive`/`blocked`) existe só no log estruturado.

Claims do token: `iss=oficina-api`, `sub`/`upn`=id do cliente, `groups=["CLIENT"]`, `clientId`, `cpf`
**mascarado** (`529******25`), `jti`, `iat`, `exp` (1 h). Assinado com **RS256 e a mesma chave privada da
aplicação**, então ela o valida sem configuração nova (verificado: a aplicação aceita um token emitido por
esta função; adulterado, recusa).

## Arquitetura

```mermaid
flowchart LR
    gw([API Gateway<br/>POST /auth/token]) --> h[AuthHandler<br/>adapter HTTP]
    subgraph fn[auth-function — Java 21 + SnapStart, dentro da VPC]
        h --> uc[AuthenticateByCpf<br/>caso de uso]
        uc --> cpf[Cpf<br/>Value Object]
        uc -->|ClientLookupPort| pg[PostgresClientLookup<br/>HikariCP max=2]
        uc -->|TokenIssuerPort| jwt[JwtTokenIssuer<br/>RS256]
    end
    pg -->|5432 + sslmode=require<br/>papel oficina_auth_ro| rds[(RDS PostgreSQL)]
    h --> log[Log JSON<br/>CloudWatch]
```

Hexagonal enxuta: `domain` (CPF, cliente), `application` (caso de uso e portas) e `infrastructure`
(handler, JDBC, JWT, config). **Sem framework** — Quarkus/Spring numa função destas é peso morto de cold
start e de superfície de CVE.

## Decisões de segurança

- Papel do banco **somente-leitura em 5 colunas** (`oficina_auth_ro`): sem `INSERT`/`UPDATE`/`DELETE` e
  sem ler e-mail nem telefone — provado por teste contra PostgreSQL real.
- A consulta ocorre **antes** de qualquer recusa de autenticação: "não existe", "inativo" e "bloqueado"
  fazem o mesmo trabalho, para o tempo de resposta não distinguir os casos.
- **Nunca** vai para o log: CPF completo, token emitido, mensagem do driver (pode conter host/banco) nem
  stack trace. Só o tipo da exceção e o `SQLState`.
- Segredos só em variáveis de ambiente (sem Secrets Manager: sem NAT as APIs públicas não são
  alcançáveis); chave privada só em memória, nada em `/tmp`.
- `Cache-Control: no-store` nas respostas (o corpo carrega um token).

## SnapStart

O pool JDBC **não** é aberto na inicialização: o socket morreria na restauração do snapshot. Ele é criado
sob demanda no primeiro atendimento. Antes do checkpoint, um hook aquece o caminho de CPF e de assinatura
(sem tocar o banco) e fecha qualquer pool. SnapStart exige versão publicada + alias (não funciona em
`$LATEST`) e proíbe imagem de container: o artefato é ZIP.

## Configuração (variáveis de ambiente)

| Variável | Obrigatória | Origem |
|---|---|---|
| `DB_HOST`, `DB_NAME` | sim | SSM (`/oficina/<env>/db_endpoint`, `db_name`), lido pelo Terraform no `apply` |
| `DB_USER` (`oficina_auth_ro`), `DB_PASSWORD` | sim | GitHub Secret do ambiente |
| `JWT_PRIVATE_KEY_PEM` | sim | GitHub Secret (o mesmo par da aplicação; PEM PKCS#8) |
| `DB_PORT` | não (5432) | |
| `JWT_ISSUER` | não (`oficina-api`) | |
| `JWT_TTL_SECONDS` | não (3600) | |

Variável ausente derruba a inicialização com a lista dos **nomes** que faltam (nunca valores).

## Pré-requisitos

JDK 21+ e Maven 3.9+. Docker, para os testes de integração (Testcontainers) e para o build reprodutível.

## Execução local

```bash
mvn verify                      # 100+ testes: unidade, contrato HTTP e PostgreSQL real; gate JaCoCo >= 80%
```

O `Testcontainers` sobe `postgres:16-alpine`. Com Docker 29+, o Testcontainers 1.x pode precisar de
`api.version=1.44` em `~/.docker-java.properties`.

## Build do artefato

```bash
docker build --target artifact --output type=local,dest=./dist .   # ./dist/auth-function.jar
```

O `Dockerfile` existe **só** para o build reprodutível; o runtime é o ZIP.

## Terraform (`terraform/`)

Dono da stack serverless da função (o API Gateway e o authorizer entram na E6):

| Recurso | Detalhe |
|---|---|
| `aws_lambda_function` | `java21`, `arm64`, 512 MB, timeout 10 s, `publish = true` + **SnapStart** em versões publicadas, concorrência reservada 10, dentro da VPC (subnets privadas) |
| `aws_lambda_alias` `live` | aponta para a versão publicada; é o alias que o gateway invoca |
| `aws_security_group` | **sem saída para a internet**: só TCP 5432 para o SG do RDS (sem NAT Gateway) |
| regra de entrada no SG do RDS | criada **aqui** (o SG do Lambda só existe depois do RDS), lendo `rds_security_group_id` do SSM |
| `aws_cloudwatch_log_group` | retenção de 7 dias (sem isto o padrão é "para sempre") |
| IAM | usa a `LabRole` existente (a conta Academy bloqueia `iam:CreateRole`) |

Rede e banco vêm do **SSM** publicado por `oficina-infra-k8s` e `oficina-infra-database`; nada é copiado à
mão. Workspaces `hml` e `prod` (o `default` é inválido de propósito), state em
`s3://oficina-tfstate-<account-id>/oficina/auth-lambda/<workspace>/terraform.tfstate`.

### Pré-requisitos do deploy

- `oficina-infra-k8s` **e** `oficina-infra-database` aplicados no mesmo workspace (senão o `plan` falha com
  `ParameterNotFound`).
- Secrets de **environment** (`homologacao` e `producao`; valores são seus, nada é commitado):

  | Secret | Valor |
  |---|---|
  | `LAMBDA_RO_PASSWORD` | senha do papel `oficina_auth_ro` — a mesma que a aplicação usa na migration V6 |
  | `JWT_PRIVATE_KEY_PEM` | a chave privada RSA (PKCS#8) **da aplicação**: a função precisa assinar com a mesma chave |

  ```bash
  gh secret set LAMBDA_RO_PASSWORD --repo victor-duarte-mendonca/oficina-auth-lambda --env homologacao
  gh secret set JWT_PRIVATE_KEY_PEM --repo victor-duarte-mendonca/oficina-auth-lambda --env homologacao < keys/privateKey.pem
  ```
- Secrets `AWS_*` (org) com a sessão Academy ativa.

## Pipeline

| Workflow / job | Gatilho | O que faz |
|---|---|---|
| `ci.yml` · `build-test` | todo push e PR | `mvn verify` (unidade + Testcontainers PostgreSQL + JaCoCo) |
| `ci.yml` · `terraform-check` | todo push e PR | `fmt`, `validate`, `tflint`, `trivy config`, `shellcheck` |
| `deploy.yml` · `package` | push e PR | JAR com dependências + checksum, como artefato |
| `deploy.yml` · `plan` | PR | `terraform plan` no workspace do alvo (`homolog`→`hml`, `main`→`prod`) comentado no PR; senhas **placeholder** (ver nota) |
| `deploy.yml` · `apply` | push em `homolog` / `main` | `apply` (publica a versão e move o alias) e **smoke test** |
| `deploy.yml` · `destroy` | `workflow_dispatch` | exige digitar `destroy-<workspace>` |

Nota sobre o `plan`: os segredos reais são de *environment*; usá-los pediria a aprovação de `producao` a cada
PR para `main`. O `plan` usa valores placeholder e mostra as variáveis de ambiente do Lambda como alteradas
(ruído esperado).

### Smoke test (`scripts/smoke-test.sh`)

Invoca o **alias** (onde o SnapStart vale), como o gateway fará: CPF inválido → 400; CPF válido
inexistente → 401, o que exercita VPC + RDS + TLS + o papel somente-leitura (500 reprova); nenhum CPF
completo no log do CloudWatch. Imprime o `REPORT` com o `Restore Duration` (prova de SnapStart).

## Destroy

Actions → `Deploy` → *Run workflow* → **Use workflow from: `homolog`** → workspace e `destroy-<workspace>`.
Ordem de encerramento: **este repositório** → `oficina-infra-database` → `oficina-infra-k8s`.

## Custo

Lambda + SnapStart: **US$ 0** para Java; dentro do nível gratuito para o volume do laboratório. A função
roda em VPC sem NAT Gateway (que custaria ≈ US$ 32/mês), só fala com o RDS.
