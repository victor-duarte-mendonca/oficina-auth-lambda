package br.com.oficina.auth.infrastructure;

import br.com.oficina.auth.application.AuthenticateByCpf;
import br.com.oficina.auth.application.AuthenticationResult;
import br.com.oficina.auth.application.AuthenticationResult.Granted;
import br.com.oficina.auth.application.AuthenticationResult.InvalidRequest;
import br.com.oficina.auth.application.AuthenticationResult.Unauthorized;
import br.com.oficina.auth.infrastructure.PostgresClientLookup.ClientLookupException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Adapter HTTP: {@code POST /auth/token} com {@code {"cpf": "..."}} (payload 2.0 do API Gateway HTTP
 * API). Traduz o {@link AuthenticationResult} em status e corpo conforme a spec 02 §2.
 *
 * <p>As três recusas de autenticação (inexistente, inativo, bloqueado) usam <b>a mesma constante</b>
 * como corpo: respostas byte a byte idênticas. A distinção existe só no log estruturado.</p>
 */
public final class AuthHandler implements RequestHandler<APIGatewayV2HTTPEvent, APIGatewayV2HTTPResponse> {

    static final String UNAUTHORIZED_BODY =
        "{\"error\":\"unauthorized\",\"message\":\"Não foi possível autenticar com os dados informados\"}";

    private static final Map<String, String> HEADERS = Map.of(
        "Content-Type", "application/json",
        // O corpo carrega um token de acesso: nenhum cache intermediário pode guardá-lo.
        "Cache-Control", "no-store",
        "Pragma", "no-cache");

    private final AuthenticateByCpf useCase;
    private final StructuredLogger log;

    /** Construtor que o runtime do Lambda invoca. */
    public AuthHandler() {
        this(Composition.useCase(), Composition.logger());
    }

    AuthHandler(AuthenticateByCpf useCase, StructuredLogger log) {
        this.useCase = useCase;
        this.log = log;
    }

    @Override
    public APIGatewayV2HTTPResponse handleRequest(APIGatewayV2HTTPEvent event, Context context) {
        long startedAt = System.nanoTime();
        String requestId = context.getAwsRequestId();
        Map<String, Object> trace = trace(event, requestId);

        try {
            String cpf = extractCpf(event);
            AuthenticationResult result = useCase.execute(cpf);
            return respond(result, trace, startedAt);
        } catch (MalformedBodyException e) {
            return invalidRequest("Corpo da requisição inválido", trace, startedAt);
        } catch (RuntimeException e) {
            return internalError(e, requestId, trace, startedAt);
        }
    }

    private APIGatewayV2HTTPResponse respond(AuthenticationResult result, Map<String, Object> trace, long startedAt) {
        return switch (result) {
            case Granted granted -> {
                log.info("auth.granted", fields(trace, startedAt,
                    "clientId", granted.client().id(), "cpfMasked", granted.cpfMasked()));
                yield response(200, grantedBody(granted));
            }
            case InvalidRequest invalid -> invalidRequest(invalid.message(), trace, startedAt);
            case Unauthorized denied -> {
                log.warn("auth.denied", fields(trace, startedAt,
                    "reason", denied.reason().name().toLowerCase(java.util.Locale.ROOT),
                    "cpfMasked", denied.cpfMasked()));
                yield response(401, UNAUTHORIZED_BODY);
            }
        };
    }

    private APIGatewayV2HTTPResponse invalidRequest(String message, Map<String, Object> trace, long startedAt) {
        log.warn("auth.invalid_request", fields(trace, startedAt));
        return response(400, json(orderedMap("error", "invalid_request", "message", message)));
    }

    private APIGatewayV2HTTPResponse internalError(RuntimeException e, String requestId,
                                                   Map<String, Object> trace, long startedAt) {
        // Só o tipo (e o SQLState): a mensagem/stack do driver pode conter host, banco ou usuário.
        Map<String, Object> fields = fields(trace, startedAt, "errorType", e.getClass().getSimpleName());
        if (e instanceof ClientLookupException lookup) {
            fields.put("sqlState", lookup.sqlState());
        }
        log.error("auth.error", fields);
        return response(500, json(orderedMap("error", "internal_error", "correlationId", requestId)));
    }

    private static String grantedBody(Granted granted) {
        Map<String, Object> client = orderedMap(
            "id", granted.client().id(), "name", granted.client().displayName());
        return json(orderedMap(
            "access_token", granted.token().accessToken(),
            "token_type", "Bearer",
            "expires_in", granted.token().expiresInSeconds(),
            "client", client));
    }

    /** Lê {@code cpf} do corpo. Corpo sem {@code cpf}, ou com valor não textual, vira CPF ausente (400). */
    private static String extractCpf(APIGatewayV2HTTPEvent event) {
        String body = event.getBody();
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            if (event.getIsBase64Encoded()) {
                body = new String(Base64.getDecoder().decode(body), StandardCharsets.UTF_8);
            }
            Object cpf = JSONObjectUtils.parse(body).get("cpf");
            return cpf instanceof String text ? text : null;
        } catch (ParseException | IllegalArgumentException e) {
            throw new MalformedBodyException();
        }
    }

    private static Map<String, Object> trace(APIGatewayV2HTTPEvent event, String requestId) {
        Map<String, Object> trace = new LinkedHashMap<>();
        // Os dois ids amarram gateway → lambda → aplicação (spec 05).
        trace.put("correlationId", requestId);
        if (event.getRequestContext() != null && event.getRequestContext().getRequestId() != null) {
            trace.put("gatewayRequestId", event.getRequestContext().getRequestId());
        }
        return trace;
    }

    private static Map<String, Object> fields(Map<String, Object> trace, long startedAt, Object... extra) {
        Map<String, Object> fields = new LinkedHashMap<>(trace);
        for (int i = 0; i < extra.length; i += 2) {
            fields.put((String) extra[i], extra[i + 1]);
        }
        fields.put("durationMs", (System.nanoTime() - startedAt) / 1_000_000);
        return fields;
    }

    private static Map<String, Object> orderedMap(Object... keyValues) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    private static String json(Map<String, Object> map) {
        return JSONObjectUtils.toJSONString(map);
    }

    private static APIGatewayV2HTTPResponse response(int status, String body) {
        return APIGatewayV2HTTPResponse.builder()
            .withStatusCode(status)
            .withHeaders(HEADERS)
            .withBody(body)
            .build();
    }

    private static final class MalformedBodyException extends RuntimeException {
        MalformedBodyException() {
            super("corpo malformado", null, false, false);
        }
    }
}
