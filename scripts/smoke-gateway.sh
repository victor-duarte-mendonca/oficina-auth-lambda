#!/usr/bin/env bash
# Smoke test ponta a ponta pelo API Gateway (spec 03 §9). Exige a aplicação implantada no mesmo workspace
# (o gateway roteia para ela) e a função de autenticação aplicada.
#
# Prova, nesta ordem:
#   1. GET /health                                  -> 200  (gateway -> Ingress -> aplicação)
#   2. POST /auth/token com CPF inválido            -> 400  (gateway -> Lambda; permissão de invocação)
#   3. POST /auth/token com CPF válido inexistente  -> 401  (Lambda -> RDS pelo papel somente-leitura)
#   4. /me sem Authorization e com token forjado    -> negado NO GATEWAY: o access log mostra que a
#      requisição não chegou ao cluster (sem latência de integração)
#   5. rajada em /auth/token                        -> ao menos um 429 (throttling por rota)
#   6. com a senha do admin semeado: login, /admin pelo authorizer + X-Gateway-Key, e o fluxo COMPLETO do
#      cliente: cria cliente -> POST /auth/token -> GET /me e /me/work-orders -> papel errado em /admin
#
# Variáveis: API_URL (obrigatória), GATEWAY_LOG_GROUP (verifica o access log), ADMIN_USER (admin),
#            ADMIN_PASSWORD (vazia = pula o fluxo autenticado). Requer curl, jq e (para o log) o aws CLI.
set -euo pipefail

API_URL="${API_URL:?API_URL obrigatória (ex.: https://abc123.execute-api.us-east-1.amazonaws.com)}"
API_URL="${API_URL%/}"
GATEWAY_LOG_GROUP="${GATEWAY_LOG_GROUP:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

fail() {
  echo "FALHOU: $*" >&2
  exit 1
}

# Só o status HTTP; o corpo nunca é impresso (pode conter token).
status() {
  curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@"
}

expect_status() {
  local description="$1" expected="$2"
  shift 2
  local got
  got="$(status "$@")"
  [ "$got" = "$expected" ] || fail "$description: esperado $expected, veio $got"
  echo "ok  $description -> $got"
}

post_json() {
  local path="$1" body="$2"
  shift 2
  curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' -d "$body" "$@" "${API_URL}${path}"
}

# CPF válido e aleatório (dígitos verificadores calculados): o fluxo do cliente cria um cliente de teste.
random_valid_cpf() {
  local digits=() i sum d1 d2
  for i in $(seq 0 8); do digits+=($((RANDOM % 10))); done
  # Evita sequências repetidas (rejeitadas pela validação).
  if [ "$(printf '%s\n' "${digits[@]}" | sort -u | wc -l)" -eq 1 ]; then digits[0]=$(( (digits[0] + 1) % 10 )); fi
  sum=0
  for i in $(seq 0 8); do sum=$((sum + digits[i] * (10 - i))); done
  d1=$(( (sum * 10) % 11 )); [ "$d1" -eq 10 ] && d1=0
  digits+=("$d1")
  sum=0
  for i in $(seq 0 9); do sum=$((sum + digits[i] * (11 - i))); done
  d2=$(( (sum * 10) % 11 )); [ "$d2" -eq 10 ] && d2=0
  digits+=("$d2")
  printf '%s' "${digits[@]}"
}

# Confere NO ACCESS LOG que a requisição foi barrada no gateway: sem latência de integração, ela nunca chegou
# ao cluster. O CloudWatch leva alguns segundos para ingerir: espera ativa.
assert_not_forwarded() {
  local request_id="$1" description="$2" message=""
  [ -n "$GATEWAY_LOG_GROUP" ] || { echo "aviso: GATEWAY_LOG_GROUP vazio — access log não verificado ($description)"; return 0; }
  for _ in $(seq 1 12); do
    message="$(aws logs filter-log-events --log-group-name "$GATEWAY_LOG_GROUP" \
      --filter-pattern "\"${request_id}\"" --query 'events[0].message' --output text 2>/dev/null || true)"
    [ -n "$message" ] && [ "$message" != "None" ] && break
    sleep 5
  done
  [ -n "$message" ] && [ "$message" != "None" ] || fail "$description: requisição ${request_id} não apareceu no access log"
  local latency
  latency="$(echo "$message" | jq -r '.integrationLatency // "-"')"
  case "$latency" in
    "-"|"") echo "ok  $description: barrada no gateway (access log sem latência de integração)" ;;
    *) fail "$description: a requisição chegou ao cluster (integrationLatency=${latency})" ;;
  esac
}

# Faz a requisição, exige que seja negada (401/403) e devolve o id da requisição do gateway.
denied_request_id() {
  local description="$1"
  shift
  local headers code request_id
  headers="$(curl -sS -D - -o /dev/null --max-time 20 "$@")"
  code="$(echo "$headers" | head -1 | awk '{print $2}')"
  case "$code" in
    401|403) echo "ok  $description -> $code" >&2 ;;
    *) fail "$description: esperado 401/403, veio $code" ;;
  esac
  request_id="$(echo "$headers" | tr -d '\r' | awk -F': ' 'tolower($1)=="apigw-requestid" {print $2}')"
  printf '%s' "$request_id"
}

echo "Gateway: ${API_URL}"

# ===== 1. saúde =====
expect_status "GET /health" 200 "${API_URL}/health"

# ===== 2 e 3. função de autenticação pelo gateway =====
code="$(post_json /auth/token '{"cpf":"111.111.111-11"}' -o /dev/null -w '%{http_code}')"
[ "$code" = "400" ] || fail "CPF inválido devolveu $code (esperado 400)"
echo "ok  POST /auth/token com CPF inválido -> 400"

unknown_cpf="390.533.447-05"
code="$(post_json /auth/token "{\"cpf\":\"${unknown_cpf}\"}" -o /dev/null -w '%{http_code}')"
case "$code" in
  401) echo "ok  POST /auth/token com CPF válido inexistente -> 401 (RDS alcançado pelo papel somente-leitura)" ;;
  200) echo "ok  POST /auth/token com CPF existente -> 200 (RDS alcançado)" ;;
  *) fail "consulta ao banco pela função devolveu $code (esperado 401/200): VPC, SG, TLS ou credencial do papel" ;;
esac

# ===== 4. negado no gateway =====
# Sem o header, o gateway responde 401 sem sequer invocar o authorizer; com um token que o authorizer recusa,
# a resposta é 403. Nos dois casos a requisição não chega ao cluster.
rid="$(denied_request_id "GET /me sem Authorization" "${API_URL}/me/work-orders")"
assert_not_forwarded "$rid" "sem Authorization"

forged="eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJvZmljaW5hLWFwaSIsInN1YiI6IjEiLCJncm91cHMiOlsiQURNSU4iXX0.QUFBQQ"
rid="$(denied_request_id "GET /me com token de assinatura forjada" -H "Authorization: Bearer ${forged}" "${API_URL}/me/work-orders")"
assert_not_forwarded "$rid" "token forjado"

# ===== 5. throttling =====
throttled=0
for _ in 1 2 3; do
  codes="$(seq 1 30 | xargs -P 30 -I{} curl -sS -o /dev/null -w '%{http_code}\n' --max-time 20 \
    -X POST -H 'Content-Type: application/json' -d '{"cpf":"111.111.111-11"}' "${API_URL}/auth/token" || true)"
  throttled="$(echo "$codes" | grep -c '^429$' || true)"
  [ "$throttled" -gt 0 ] && break
  sleep 2
done
[ "$throttled" -gt 0 ] || fail "30 requisições simultâneas em /auth/token não geraram nenhum 429 (throttling por rota)"
echo "ok  rajada em /auth/token -> ${throttled} resposta(s) 429"
sleep 3 # deixa o balde do throttling encher antes do fluxo autenticado

# ===== 6. fluxo autenticado =====
if [ -z "$ADMIN_PASSWORD" ]; then
  echo "aviso: sem senha do admin semeado (seed desligado) — fluxo autenticado e fluxo do cliente pulados"
  echo "Smoke test do gateway concluído."
  exit 0
fi

admin_token="$(post_json /auth/login \
  "$(jq -cn --arg u "$ADMIN_USER" --arg p "$ADMIN_PASSWORD" '{username: $u, password: $p}')" | jq -r '.token // empty')"
[ -n "$admin_token" ] || fail "login do admin pelo gateway não devolveu token"
echo "ok  POST /auth/login pelo gateway -> token"

expect_status "GET /admin/clients com token de ADMIN (authorizer + X-Gateway-Key + aplicação)" 200 \
  -H "Authorization: Bearer ${admin_token}" "${API_URL}/admin/clients"

# O fluxo completo do cliente (critério de aceite da spec 03): cria o cliente, autentica por CPF e consome /me.
cpf="$(random_valid_cpf)"
create_status="$(post_json /admin/clients \
  "$(jq -cn --arg cpf "$cpf" '{name: "Smoke Gateway", cpfCnpj: $cpf, clientType: "PF", email: "smoke.gateway@example.com"}')" \
  -H "Authorization: Bearer ${admin_token}" -o /tmp/smoke-client.json -w '%{http_code}')"
[ "$create_status" = "201" ] || fail "criação do cliente de teste devolveu $create_status (esperado 201)"
client_id="$(jq -r '.id' /tmp/smoke-client.json)"
echo "ok  cliente de teste criado (id ${client_id})"

client_token="$(post_json /auth/token "$(jq -cn --arg cpf "$cpf" '{cpf: $cpf}')" | jq -r '.access_token // empty')"
[ -n "$client_token" ] || fail "POST /auth/token com o CPF do cliente de teste não devolveu access_token"
echo "ok  POST /auth/token com CPF do cliente -> access_token"

expect_status "GET /me com o token do cliente" 200 -H "Authorization: Bearer ${client_token}" "${API_URL}/me"
expect_status "GET /me/work-orders com o token do cliente" 200 -H "Authorization: Bearer ${client_token}" "${API_URL}/me/work-orders"
# O authorizer deixa o CLIENT passar; quem nega é a aplicação (camada 2: nenhuma das duas confia na outra).
expect_status "token de CLIENT em rota de oficina (papel errado, negado pela aplicação)" 403 \
  -H "Authorization: Bearer ${client_token}" "${API_URL}/admin/clients"

# Limpeza do cliente de teste (melhor esforço).
curl -sS -o /dev/null --max-time 20 -X DELETE -H "Authorization: Bearer ${admin_token}" \
  "${API_URL}/admin/clients/${client_id}" || true

echo "Smoke test do gateway concluído."
