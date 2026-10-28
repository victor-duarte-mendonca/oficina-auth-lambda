import assert from "node:assert/strict";
import { gunzipSync, gzipSync } from "node:zlib";
import { test } from "node:test";
import { createHandler, decode, toLog, toPayload } from "./index.mjs";

function cloudWatchEvent(body) {
  return { awslogs: { data: gzipSync(JSON.stringify(body)).toString("base64") } };
}

const dataMessage = (logEvents, logGroup = "/aws/lambda/oficina-hml-auth-token") => ({
  messageType: "DATA_MESSAGE",
  logGroup,
  logStream: "2026/10/28/[$LATEST]abc",
  logEvents,
});

test("linha JSON vira atributos pesquisáveis, com correlationId", () => {
  const log = toLog({
    timestamp: 1730000000000,
    message: '{"event":"auth.denied","correlationId":"req-1","message":"negado","latencyMs":12}\n',
  });
  assert.equal(log.message, "negado");
  assert.equal(log.attributes.correlationId, "req-1");
  assert.equal(log.attributes.event, "auth.denied");
  assert.equal(log.attributes.latencyMs, 12);
});

test("JSON sem message mantém a linha original como mensagem", () => {
  const raw = '{"requestId":"JIK9Ngt5IAMEJHg=","status":"200"}';
  const log = toLog({ timestamp: 1, message: raw });
  assert.equal(log.message, raw);
  assert.equal(log.attributes.requestId, "JIK9Ngt5IAMEJHg=");
});

test("texto e JSON malformado seguem como texto, sem atributos", () => {
  assert.deepEqual(toLog({ timestamp: 1, message: "START RequestId: abc" }), {
    timestamp: 1,
    message: "START RequestId: abc",
  });
  assert.equal(toLog({ timestamp: 1, message: "{quebrado" }).attributes, undefined);
});

test("atributos comuns trazem serviço, ambiente e origem", () => {
  const [batch] = toPayload(dataMessage([{ timestamp: 1, message: "x" }]), "hml");
  assert.equal(batch.common.attributes["service.name"], "oficina-hml-auth-token");
  assert.equal(batch.common.attributes.env, "hml");
  assert.equal(batch.common.attributes.source, "cloudwatch");
  assert.equal(batch.logs.length, 1);
});

test("mensagem de controle do CloudWatch é ignorada", () => {
  assert.equal(decode(cloudWatchEvent({ messageType: "CONTROL_MESSAGE" })), null);
});

test("handler envia gzip com a licença no cabeçalho e lê a licença uma única vez", async () => {
  const calls = [];
  let licenseReads = 0;
  const handler = createHandler({
    loadLicense: async () => {
      licenseReads += 1;
      return "licenca-de-teste";
    },
    fetchFn: async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 202 };
    },
  });
  const event = cloudWatchEvent(dataMessage([{ timestamp: 1, message: '{"correlationId":"c-1"}' }]));

  assert.deepEqual(await handler(event), { forwarded: 1 });
  await handler(event);

  assert.equal(licenseReads, 1);
  assert.equal(calls[0].init.headers["Api-Key"], "licenca-de-teste");
  assert.equal(calls[0].init.headers["Content-Encoding"], "gzip");
  const sent = JSON.parse(gunzipSync(calls[0].init.body).toString("utf8"));
  assert.equal(sent[0].logs[0].attributes.correlationId, "c-1");
});

test("erro da Log API falha o handler sem vazar a licença", async () => {
  const handler = createHandler({
    loadLicense: async () => "licenca-secreta",
    fetchFn: async () => ({ ok: false, status: 403 }),
  });
  const event = cloudWatchEvent(dataMessage([{ timestamp: 1, message: "x" }]));

  await assert.rejects(handler(event), (error) => {
    assert.match(error.message, /403/);
    assert.ok(!error.message.includes("licenca-secreta"));
    return true;
  });
});
