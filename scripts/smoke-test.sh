#!/usr/bin/env bash
# Smoke test da função implantada (spec 02 §9), invocando o ALIAS (onde o SnapStart vale), como o API
# Gateway fará. Prova, de ponta a ponta e sem depender de dados semeados:
#   1. CPF inválido            -> 400  (validação, sem banco)
#   2. CPF válido inexistente  -> 401  (exercita VPC + RDS + TLS + papel somente-leitura; 500 = falha)
#   3. nenhum CPF completo no log (CloudWatch)
# Imprime também o REPORT da primeira invocação (inclui "Restore Duration" quando o SnapStart está ativo).
#
# Uso: scripts/smoke-test.sh <nome-da-função> [alias]   (com credenciais AWS no ambiente)
set -euo pipefail

FUNCTION="${1:?uso: smoke-test.sh <função> [alias]}"
ALIAS="${2:-live}"

INVALID_CPF="111.111.111-11"            # sequência repetida: sempre 400
UNKNOWN_CPF="390.533.447-05"            # CPF válido que não deve existir na base
UNKNOWN_CPF_DIGITS="39053344705"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Invoca com um evento no formato 2.0 do API Gateway HTTP API; imprime o statusCode e guarda o log.
invoke() {
  local cpf="$1" tag="$2"
  jq -n --arg body "$(jq -cn --arg cpf "$cpf" '{cpf: $cpf}')" \
    '{version: "2.0", body: $body, isBase64Encoded: false, requestContext: {requestId: "smoke-test"}}' \
    > "$work/event.json"
  aws lambda invoke --function-name "${FUNCTION}:${ALIAS}" --payload "fileb://$work/event.json" \
    --log-type Tail --query 'LogResult' --output text "$work/out-$tag.json" | base64 -d > "$work/log-$tag.txt"
  jq -r '.statusCode' "$work/out-$tag.json"
}

fail() {
  echo "FALHOU: $*" >&2
  exit 1
}

echo "Invocando ${FUNCTION}:${ALIAS}"

status_invalid="$(invoke "$INVALID_CPF" invalid)"
[ "$status_invalid" = "400" ] || fail "CPF inválido devolveu $status_invalid (esperado 400)"
echo "ok  CPF inválido -> 400"

status_unknown="$(invoke "$UNKNOWN_CPF" unknown)"
case "$status_unknown" in
  401) echo "ok  CPF válido inexistente -> 401 (banco alcançado pelo papel somente-leitura)" ;;
  200) echo "ok  CPF válido existente -> 200 (banco alcançado)" ;;
  *)
    echo "--- log da invocação ---" >&2
    cat "$work/log-unknown.txt" >&2
    fail "consulta ao banco devolveu $status_unknown (esperado 401/200): VPC, SG, TLS ou credencial do papel"
    ;;
esac

# A resposta de 401 deve ser a constante do contrato, sem pistas do motivo.
if [ "$status_unknown" = "401" ]; then
  jq -e '.body | fromjson | .error == "unauthorized"' "$work/out-unknown.json" > /dev/null \
    || fail "corpo do 401 fora do contrato"
fi

report="$(grep -h '^REPORT' "$work"/log-*.txt | head -1 || true)"
echo "REPORT: ${report:-<indisponível>}"
if echo "$report" | grep -q "Restore Duration"; then
  echo "ok  SnapStart ativo (Restore Duration presente)"
else
  echo "aviso: sem 'Restore Duration' no REPORT (invocação não veio de um snapshot restaurado)"
fi

# Nenhum CPF completo no log: o filtro roda no log group depois de uma pequena espera de ingestão.
sleep 10
leaked="$(aws logs filter-log-events --log-group-name "/aws/lambda/${FUNCTION}" \
  --filter-pattern "\"${UNKNOWN_CPF_DIGITS}\"" --query 'length(events)' --output text)"
[ "$leaked" = "0" ] || fail "o CPF completo apareceu em $leaked evento(s) de log"
echo "ok  nenhum CPF completo no log"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Smoke test — ${FUNCTION}:${ALIAS}"
    echo ""
    echo "- CPF inválido: 400"
    echo "- CPF válido inexistente: ${status_unknown} (banco alcançado)"
    echo "- ${report:-REPORT indisponível}"
  } >> "$GITHUB_STEP_SUMMARY"
fi
