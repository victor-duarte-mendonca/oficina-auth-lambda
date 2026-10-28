// Encaminha logs do CloudWatch (access log do gateway e logs JSON dos dois Lambdas) para a Log API do
// New Relic (spec 05 §3). Os Lambdas rodam em VPC sem NAT e não têm internet: a saída é o CloudWatch, e
// este forwarder, FORA da VPC, é quem fala com o New Relic. Substitui o newrelic-log-ingestion do SAR,
// cujo CloudFormation cria IAM role (bloqueado no AWS Academy).
//
// A licença é lida do SSM (SecureString) na inicialização a frio; não fica em variável de ambiente.
import { gunzipSync, gzipSync } from "node:zlib";

const LOG_API = process.env.NEW_RELIC_LOG_ENDPOINT ?? "https://log-api.newrelic.com/log/v1";

/** Descompacta o evento de assinatura do CloudWatch Logs; null para mensagens de controle. */
export function decode(event) {
  const body = JSON.parse(gunzipSync(Buffer.from(event.awslogs.data, "base64")).toString("utf8"));
  return body.messageType === "DATA_MESSAGE" ? body : null;
}

/** "/aws/lambda/oficina-hml-auth-token" -> "oficina-hml-auth-token"; "/oficina/hml/gateway" -> "gateway". */
function serviceOf(logGroup) {
  return logGroup.split("/").filter(Boolean).pop();
}

/**
 * Um log do CloudWatch vira um log do New Relic. Se a linha é JSON (StructuredLogger dos Lambdas e access log
 * do gateway), os campos viram atributos pesquisáveis — é assim que "correlationId" fica filtrável.
 */
export function toLog(logEvent) {
  const raw = logEvent.message.trimEnd();
  const log = { timestamp: logEvent.timestamp, message: raw };
  if (!raw.startsWith("{")) {
    return log;
  }
  try {
    const fields = JSON.parse(raw);
    if (fields !== null && typeof fields === "object" && !Array.isArray(fields)) {
      const { message, ...attributes } = fields;
      return {
        timestamp: logEvent.timestamp,
        message: typeof message === "string" ? message : raw,
        attributes,
      };
    }
  } catch {
    // JSON malformado: segue como texto.
  }
  return log;
}

export function toPayload(body, environment) {
  return [
    {
      common: {
        attributes: {
          "service.name": serviceOf(body.logGroup),
          env: environment,
          logGroup: body.logGroup,
          logStream: body.logStream,
          source: "cloudwatch",
        },
      },
      logs: body.logEvents.map(toLog),
    },
  ];
}

async function ssmLicense() {
  const { SSMClient, GetParameterCommand } = await import("@aws-sdk/client-ssm");
  const out = await new SSMClient({}).send(
    new GetParameterCommand({ Name: process.env.LICENSE_SSM_NAME, WithDecryption: true }),
  );
  return out.Parameter.Value;
}

export function createHandler({ loadLicense = ssmLicense, fetchFn = fetch } = {}) {
  let license; // cache da inicialização a frio

  return async (event) => {
    const body = decode(event);
    if (body === null) {
      return { forwarded: 0 };
    }
    license ??= await loadLicense();

    const payload = gzipSync(JSON.stringify(toPayload(body, process.env.SERVICE_ENV ?? "unknown")));
    const response = await fetchFn(LOG_API, {
      method: "POST",
      headers: {
        "Api-Key": license,
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
      },
      body: payload,
    });
    if (!response.ok) {
      // Nunca incluir o corpo/cabeçalhos no erro: a licença está no cabeçalho.
      throw new Error(`Log API do New Relic respondeu ${response.status}`);
    }
    return { forwarded: body.logEvents.length };
  };
}

export const handler = createHandler();
