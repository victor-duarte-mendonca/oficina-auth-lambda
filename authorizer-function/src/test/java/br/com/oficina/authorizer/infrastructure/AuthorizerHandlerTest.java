package br.com.oficina.authorizer.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.oficina.authorizer.application.AuthorizeRequest;
import com.amazonaws.services.lambda.runtime.ClientContext;
import com.amazonaws.services.lambda.runtime.CognitoIdentity;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2CustomAuthorizerEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Contrato com o gateway: resposta simples, sem detalhe na recusa, e nada de token no log. */
class AuthorizerHandlerTest {

    private static final String REQUEST_ID = "lambda-req-1";
    private static final String GATEWAY_REQUEST_ID = "gw-req-2";

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;
    private static RSAPrivateKey attackerKey;

    private final ByteArrayOutputStream logOutput = new ByteArrayOutputStream();
    private final AuthorizerHandler handler = new AuthorizerHandler(
        new AuthorizeRequest(new JwtVerifier(publicKey, "oficina-api", Duration.ofSeconds(30), Clock.systemUTC())),
        new StructuredLogger(new PrintStream(logOutput, true, StandardCharsets.UTF_8)));

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
        attackerKey = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
    }

    private static String token(RSAPrivateKey key, String subject, List<String> groups, Object clientId) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("oficina-api").subject(subject)
            .claim("groups", groups).expirationTime(new Date(System.currentTimeMillis() + 3_600_000));
        if (clientId != null) {
            claims.claim("clientId", clientId);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static APIGatewayV2CustomAuthorizerEvent eventWithHeaders(Map<String, String> headers) {
        APIGatewayV2CustomAuthorizerEvent event = new APIGatewayV2CustomAuthorizerEvent();
        event.setHeaders(headers);
        event.setRouteKey("GET /me/{proxy+}");
        APIGatewayV2CustomAuthorizerEvent.RequestContext requestContext =
            new APIGatewayV2CustomAuthorizerEvent.RequestContext();
        requestContext.setRequestId(GATEWAY_REQUEST_ID);
        event.setRequestContext(requestContext);
        return event;
    }

    private Map<String, Object> call(APIGatewayV2CustomAuthorizerEvent event) {
        return handler.handleRequest(event, new StubContext());
    }

    private String logs() {
        return logOutput.toString(StandardCharsets.UTF_8);
    }

    // ===== autorizado =====

    @Test
    void validClientToken_shouldBeAuthorizedWithTheCallerContext() throws Exception {
        String jwt = token(privateKey, "42", List.of("CLIENT"), 42L);

        Map<String, Object> response = call(eventWithHeaders(Map.of("authorization", "Bearer " + jwt)));

        assertThat(response).containsEntry("isAuthorized", true);
        @SuppressWarnings("unchecked")
        Map<String, Object> context = (Map<String, Object>) response.get("context");
        // Valores de contexto do HTTP API: só string/número/booleano.
        assertThat(context).containsEntry("role", "CLIENT").containsEntry("sub", "42").containsEntry("clientId", "42");
    }

    @Test
    void staffToken_shouldBeAuthorizedWithoutClientId() throws Exception {
        String jwt = token(privateKey, "admin", List.of("ADMIN"), null);

        Map<String, Object> response = call(eventWithHeaders(Map.of("authorization", "Bearer " + jwt)));

        @SuppressWarnings("unchecked")
        Map<String, Object> context = (Map<String, Object>) response.get("context");
        assertThat(response).containsEntry("isAuthorized", true);
        assertThat(context).containsEntry("role", "ADMIN").doesNotContainKey("clientId");
    }

    @Test
    void headerName_shouldBeReadIgnoringCase() throws Exception {
        String jwt = token(privateKey, "42", List.of("CLIENT"), 42L);

        assertThat(call(eventWithHeaders(Map.of("Authorization", "Bearer " + jwt)))).containsEntry("isAuthorized", true);
        assertThat(call(eventWithHeaders(Map.of("AUTHORIZATION", "Bearer " + jwt)))).containsEntry("isAuthorized", true);
    }

    @Test
    void identitySource_shouldBeUsedWhenTheHeaderMapHasNoAuthorization() throws Exception {
        String jwt = token(privateKey, "42", List.of("CLIENT"), 42L);
        APIGatewayV2CustomAuthorizerEvent event = eventWithHeaders(Map.of("x-outro", "valor"));
        event.setIdentitySource(List.of("Bearer " + jwt));

        assertThat(call(event)).containsEntry("isAuthorized", true);
    }

    // ===== negado =====

    @Test
    void noAuthorizationHeader_shouldBeDeniedWithAnEmptyBody() {
        Map<String, Object> response = call(eventWithHeaders(Map.of("x-outro", "valor")));

        // Sem "context" e sem motivo: o chamador não deve aprender o que errou.
        assertThat(response).isEqualTo(Map.of("isAuthorized", false));
    }

    @Test
    void nullHeaders_shouldBeDeniedWithoutFailing() {
        APIGatewayV2CustomAuthorizerEvent event = new APIGatewayV2CustomAuthorizerEvent();

        assertThat(call(event)).isEqualTo(Map.of("isAuthorized", false));
    }

    @Test
    void forgedToken_shouldBeDenied() throws Exception {
        String forged = token(attackerKey, "42", List.of("ADMIN"), 42L);

        assertThat(call(eventWithHeaders(Map.of("authorization", "Bearer " + forged))))
            .isEqualTo(Map.of("isAuthorized", false));
    }

    @Test
    void tokenWithAnUnknownRole_shouldBeDenied() throws Exception {
        String jwt = token(privateKey, "42", List.of("SUPERUSER"), 42L);

        assertThat(call(eventWithHeaders(Map.of("authorization", "Bearer " + jwt))))
            .isEqualTo(Map.of("isAuthorized", false));
    }

    @Test
    void anUnexpectedFailure_shouldFailClosedAndLogOnlyTheType() {
        AuthorizerHandler failing = new AuthorizerHandler(
            new AuthorizeRequest(token -> {
                throw new IllegalStateException("detalhe interno com o token eyJSECRETO");
            }),
            new StructuredLogger(new PrintStream(logOutput, true, StandardCharsets.UTF_8)));
        Map<String, Object> response = failing.handleRequest(
            eventWithHeaders(Map.of("authorization", "Bearer abc.def.ghi")), new StubContext());

        assertThat(response).isEqualTo(Map.of("isAuthorized", false));
        assertThat(logs()).doesNotContain("eyJSECRETO");
    }

    // ===== log =====

    @Test
    void denialLog_shouldCarryTheReasonAndBothCorrelationIdsButNeverTheToken() throws Exception {
        String forged = token(attackerKey, "42", List.of("ADMIN"), 42L);

        call(eventWithHeaders(Map.of("authorization", "Bearer " + forged)));

        String logs = logs();
        assertThat(logs).contains("\"event\":\"authorizer.denied\"").contains("\"reason\":\"bad_signature\"")
            .contains("\"correlationId\":\"" + REQUEST_ID + "\"")
            .contains("\"gatewayRequestId\":\"" + GATEWAY_REQUEST_ID + "\"")
            .contains("\"routeKey\":\"GET /me/{proxy+}\"");
        assertThat(logs).doesNotContain(forged).doesNotContain(forged.split("\\.")[1]).doesNotContain("Bearer");
    }

    @Test
    void allowedLog_shouldCarryTheRoleButNeverTheToken() throws Exception {
        String jwt = token(privateKey, "42", List.of("CLIENT"), 42L);

        call(eventWithHeaders(Map.of("authorization", "Bearer " + jwt)));

        assertThat(logs()).contains("\"event\":\"authorizer.allowed\"").contains("\"role\":\"CLIENT\"")
            .doesNotContain(jwt).doesNotContain("Bearer");
    }

    @Test
    void logs_shouldBeOneJsonObjectPerLine() throws Exception {
        call(eventWithHeaders(Map.of("authorization", "Bearer " + token(privateKey, "42", List.of("CLIENT"), 42L))));
        call(eventWithHeaders(Map.of("x", "y")));

        for (String line : logs().strip().split("\n")) {
            assertThat(JSONObjectUtils.parse(line)).containsKeys("level", "event");
        }
    }

    /** Contexto mínimo do Lambda: só o que o handler lê. */
    private static final class StubContext implements Context {
        @Override public String getAwsRequestId() { return REQUEST_ID; }
        @Override public String getLogGroupName() { return "/aws/lambda/test"; }
        @Override public String getLogStreamName() { return "stream"; }
        @Override public String getFunctionName() { return "authorizer"; }
        @Override public String getFunctionVersion() { return "1"; }
        @Override public String getInvokedFunctionArn() { return "arn:aws:lambda:us-east-1:0:function:authorizer"; }
        @Override public CognitoIdentity getIdentity() { return null; }
        @Override public ClientContext getClientContext() { return null; }
        @Override public int getRemainingTimeInMillis() { return 5_000; }
        @Override public int getMemoryLimitInMB() { return 512; }
        @Override public LambdaLogger getLogger() {
            return new LambdaLogger() {
                @Override public void log(String message) { }
                @Override public void log(byte[] message) { }
            };
        }
    }
}
