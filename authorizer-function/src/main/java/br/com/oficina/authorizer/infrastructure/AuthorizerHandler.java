package br.com.oficina.authorizer.infrastructure;

import br.com.oficina.authorizer.application.AuthorizationDecision;
import br.com.oficina.authorizer.application.AuthorizationDecision.Allowed;
import br.com.oficina.authorizer.application.AuthorizationDecision.Denied;
import br.com.oficina.authorizer.application.AuthorizeRequest;
import br.com.oficina.authorizer.domain.AuthorizedCaller;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Adapter do Lambda authorizer do API Gateway (HTTP API, payload 2.0, <i>simple response</i>). Traduz a
 * decisão em {@code {"isAuthorized": ...}}; o contexto devolvido segue para a integração, mas a
 * aplicação não confia nele — ela revalida o JWT por conta própria.
 *
 * <p>Nunca lança: qualquer falha inesperada vira {@code isAuthorized=false}. Falhar fechado é o
 * comportamento seguro.</p>
 */
public final class AuthorizerHandler
    implements RequestHandler<APIGatewayV2CustomAuthorizerEvent, Map<String, Object>> {

    private static final String AUTHORIZATION = "authorization";

    private final AuthorizeRequest authorize;
    private final StructuredLogger log;

    /** Construtor que o runtime do Lambda invoca. */
    public AuthorizerHandler() {
        this(Composition.authorize(), Composition.logger());
    }

    AuthorizerHandler(AuthorizeRequest authorize, StructuredLogger log) {
        this.authorize = authorize;
        this.log = log;
    }

    @Override
    public Map<String, Object> handleRequest(APIGatewayV2CustomAuthorizerEvent event, Context context) {
        Map<String, Object> trace = trace(event, context);
        try {
            AuthorizationDecision decision = authorize.execute(authorizationHeaderOf(event));
            return switch (decision) {
                case Allowed allowed -> allow(allowed.caller(), trace);
                case Denied denied -> deny(denied.reason().name().toLowerCase(Locale.ROOT), trace);
            };
        } catch (RuntimeException e) {
            // Só o tipo: o motivo detalhado pode conter pedaços do token.
            Map<String, Object> fields = new LinkedHashMap<>(trace);
            fields.put("errorType", e.getClass().getSimpleName());
            log.error("authorizer.error", fields);
            return Map.of("isAuthorized", false);
        }
    }

    private Map<String, Object> allow(AuthorizedCaller caller, Map<String, Object> trace) {
        Map<String, Object> fields = new LinkedHashMap<>(trace);
        fields.put("role", caller.role().name());
        fields.put("sub", caller.subject());
        log.info("authorizer.allowed", fields);

        // Valores de contexto do HTTP API: só string, número ou booleano.
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("role", caller.role().name());
        context.put("sub", caller.subject());
        caller.clientId().ifPresent(id -> context.put("clientId", String.valueOf(id)));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("isAuthorized", true);
        response.put("context", context);
        return response;
    }

    private Map<String, Object> deny(String reason, Map<String, Object> trace) {
        Map<String, Object> fields = new LinkedHashMap<>(trace);
        fields.put("reason", reason);
        log.warn("authorizer.denied", fields);
        // Sem detalhe ao chamador: ele não deve aprender o que errou.
        return Map.of("isAuthorized", false);
    }

    /** Lê o header sem depender de caixa; cai para a identity source, que o gateway também preenche. */
    private static String authorizationHeaderOf(APIGatewayV2CustomAuthorizerEvent event) {
        Map<String, String> headers = event.getHeaders();
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (AUTHORIZATION.equalsIgnoreCase(header.getKey())) {
                    return header.getValue();
                }
            }
        }
        List<String> identitySource = event.getIdentitySource();
        return identitySource == null || identitySource.isEmpty() ? null : identitySource.get(0);
    }

    private static Map<String, Object> trace(APIGatewayV2CustomAuthorizerEvent event, Context context) {
        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("correlationId", context.getAwsRequestId());
        if (event.getRequestContext() != null && event.getRequestContext().getRequestId() != null) {
            trace.put("gatewayRequestId", event.getRequestContext().getRequestId());
        }
        if (event.getRouteKey() != null) {
            trace.put("routeKey", event.getRouteKey());
        }
        return trace;
    }
}
