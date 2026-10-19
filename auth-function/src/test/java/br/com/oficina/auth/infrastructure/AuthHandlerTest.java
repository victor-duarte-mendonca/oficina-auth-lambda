package br.com.oficina.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.oficina.auth.application.AuthenticateByCpf;
import br.com.oficina.auth.application.ClientLookupPort;
import br.com.oficina.auth.application.TokenIssuerPort;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.ClientStatus;
import com.amazonaws.services.lambda.runtime.ClientContext;
import com.amazonaws.services.lambda.runtime.CognitoIdentity;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Contrato HTTP da função (spec 02 §2), com o caso de uso real e portas em memória. */
class AuthHandlerTest {

    private static final String VALID_CPF = "529.982.247-25";
    private static final String LAMBDA_REQUEST_ID = "lambda-req-123";
    private static final String GATEWAY_REQUEST_ID = "gw-req-456";

    private final ByteArrayOutputStream logOutput = new ByteArrayOutputStream();

    private AuthHandler handlerFor(Supplier<Optional<ClientAccount>> lookup) {
        ClientLookupPort clients = cpf -> lookup.get();
        TokenIssuerPort tokens = (client, cpf) -> new TokenIssuerPort.IssuedToken("jwt-do-cliente-" + client.id(), 3600);
        return new AuthHandler(new AuthenticateByCpf(clients, tokens),
            new StructuredLogger(new PrintStream(logOutput, true, StandardCharsets.UTF_8)));
    }

    private AuthHandler handlerWith(ClientStatus status) {
        return handlerFor(() -> Optional.of(new ClientAccount(42, "Maria Souza", status)));
    }

    private static APIGatewayV2HTTPEvent eventWithBody(String body) {
        return APIGatewayV2HTTPEvent.builder()
            .withBody(body)
            .withRequestContext(APIGatewayV2HTTPEvent.RequestContext.builder().withRequestId(GATEWAY_REQUEST_ID).build())
            .build();
    }

    private static APIGatewayV2HTTPEvent eventWithCpf(String cpf) {
        return eventWithBody("{\"cpf\": \"" + cpf + "\"}");
    }

    private APIGatewayV2HTTPResponse call(AuthHandler handler, APIGatewayV2HTTPEvent event) {
        return handler.handleRequest(event, new StubContext());
    }

    private String logs() {
        return logOutput.toString(StandardCharsets.UTF_8);
    }

    private static Map<String, Object> bodyOf(APIGatewayV2HTTPResponse response) throws Exception {
        return JSONObjectUtils.parse(response.getBody());
    }

    // ===== 200 =====

    @Test
    void validActiveCpf_shouldReturn200WithTheTokenAndTheClientSummary() throws Exception {
        APIGatewayV2HTTPResponse response = call(handlerWith(ClientStatus.ACTIVE), eventWithCpf(VALID_CPF));

        assertThat(response.getStatusCode()).isEqualTo(200);
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("access_token", "jwt-do-cliente-42")
            .containsEntry("token_type", "Bearer").containsEntry("expires_in", 3600L);
        assertThat(JSONObjectUtils.getJSONObject(body, "client"))
            .containsEntry("id", 42L).containsEntry("name", "Maria S.");
    }

    @Test
    void response_shouldForbidCachingBecauseTheBodyCarriesAToken() {
        APIGatewayV2HTTPResponse response = call(handlerWith(ClientStatus.ACTIVE), eventWithCpf(VALID_CPF));

        assertThat(response.getHeaders()).containsEntry("Cache-Control", "no-store")
            .containsEntry("Content-Type", "application/json");
    }

    @Test
    void cpfWithoutMask_andBase64Body_shouldAlsoWork() {
        String encoded = Base64.getEncoder().encodeToString("{\"cpf\":\"52998224725\"}".getBytes(StandardCharsets.UTF_8));
        APIGatewayV2HTTPEvent event = APIGatewayV2HTTPEvent.builder().withBody(encoded).withIsBase64Encoded(true).build();

        assertThat(call(handlerWith(ClientStatus.ACTIVE), event).getStatusCode()).isEqualTo(200);
    }

    // ===== 400 =====

    @Test
    void invalidCpf_shouldReturn400WithTheContractBody() throws Exception {
        APIGatewayV2HTTPResponse response = call(handlerWith(ClientStatus.ACTIVE), eventWithCpf("529.982.247-24"));

        assertThat(response.getStatusCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request").containsEntry("message", "CPF inválido");
    }

    @Test
    void repeatedSequenceCpf_shouldReturn400() {
        assertThat(call(handlerWith(ClientStatus.ACTIVE), eventWithCpf("111.111.111-11")).getStatusCode()).isEqualTo(400);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"cpf\": 52998224725}", "{\"cpf\": null}", "{\"outro\": \"x\"}", ""})
    void missingOrNonTextCpf_shouldReturn400(String body) {
        assertThat(call(handlerWith(ClientStatus.ACTIVE), eventWithBody(body)).getStatusCode()).isEqualTo(400);
    }

    @Test
    void nullBody_shouldReturn400() {
        assertThat(call(handlerWith(ClientStatus.ACTIVE), eventWithBody(null)).getStatusCode()).isEqualTo(400);
    }

    @ParameterizedTest
    @ValueSource(strings = {"isto nao e json", "[1,2]", "{\"cpf\": "})
    void malformedBody_shouldReturn400WithoutAnInternalError(String body) throws Exception {
        APIGatewayV2HTTPResponse response = call(handlerWith(ClientStatus.ACTIVE), eventWithBody(body));

        assertThat(response.getStatusCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
    }

    @Test
    void invalidBase64Body_shouldReturn400() {
        APIGatewayV2HTTPEvent event = APIGatewayV2HTTPEvent.builder().withBody("%%%nao-e-base64").withIsBase64Encoded(true).build();

        assertThat(call(handlerWith(ClientStatus.ACTIVE), event).getStatusCode()).isEqualTo(400);
    }

    // ===== 401 =====

    /** Inexistente, inativo e bloqueado: respostas byte a byte idênticas (anti-enumeração de clientes). */
    @Test
    void notFoundInactiveAndBlocked_shouldProduceByteIdenticalResponses() {
        APIGatewayV2HTTPResponse notFound = call(handlerFor(Optional::empty), eventWithCpf(VALID_CPF));
        APIGatewayV2HTTPResponse blocked = call(handlerWith(ClientStatus.BLOCKED), eventWithCpf(VALID_CPF));
        APIGatewayV2HTTPResponse inactive = call(handlerWith(ClientStatus.INACTIVE), eventWithCpf(VALID_CPF));

        assertThat(notFound.getStatusCode()).isEqualTo(401);
        assertThat(blocked.getBody()).isEqualTo(notFound.getBody());
        assertThat(inactive.getBody()).isEqualTo(notFound.getBody());
        assertThat(blocked.getStatusCode()).isEqualTo(notFound.getStatusCode());
        assertThat(inactive.getHeaders()).isEqualTo(notFound.getHeaders());
        assertThat(notFound.getBody()).isEqualTo(AuthHandler.UNAUTHORIZED_BODY);
    }

    @Test
    void deniedResponse_shouldNotRevealWhyInTheBody() {
        String body = call(handlerWith(ClientStatus.BLOCKED), eventWithCpf(VALID_CPF)).getBody().toLowerCase();

        assertThat(body).doesNotContain("bloquead").doesNotContain("blocked").doesNotContain("inativ")
            .doesNotContain("não encontrad").doesNotContain("not_found");
    }

    @Test
    void theDenialReason_shouldBeInTheOperatorLogOnly() {
        call(handlerWith(ClientStatus.BLOCKED), eventWithCpf(VALID_CPF));
        call(handlerFor(Optional::empty), eventWithCpf(VALID_CPF));
        call(handlerWith(ClientStatus.INACTIVE), eventWithCpf(VALID_CPF));

        assertThat(logs()).contains("\"reason\":\"blocked\"").contains("\"reason\":\"not_found\"")
            .contains("\"reason\":\"inactive\"");
    }

    // ===== 500 =====

    @Test
    void infrastructureFailure_shouldReturn500WithTheCorrelationIdAndNoInternals() throws Exception {
        AuthHandler failing = handlerFor(() -> {
            throw new IllegalStateException("jdbc:postgresql://host-interno-secreto:5432/oficina_db falhou");
        });

        APIGatewayV2HTTPResponse response = call(failing, eventWithCpf(VALID_CPF));

        assertThat(response.getStatusCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsEntry("error", "internal_error")
            .containsEntry("correlationId", LAMBDA_REQUEST_ID);
        assertThat(response.getBody()).doesNotContain("host-interno-secreto").doesNotContain("Exception");
        // O log traz o tipo, mas nunca a mensagem do driver (que pode conter host/banco).
        assertThat(logs()).contains("\"errorType\":\"IllegalStateException\"").doesNotContain("host-interno-secreto");
    }

    // ===== Log =====

    @Test
    void logs_shouldCarryBothCorrelationIdsAndOnlyTheMaskedCpf() {
        call(handlerWith(ClientStatus.ACTIVE), eventWithCpf(VALID_CPF));

        String logs = logs();
        assertThat(logs).contains("\"event\":\"auth.granted\"").contains("\"clientId\":42")
            .contains("\"cpfMasked\":\"529******25\"")
            .contains("\"correlationId\":\"" + LAMBDA_REQUEST_ID + "\"")
            .contains("\"gatewayRequestId\":\"" + GATEWAY_REQUEST_ID + "\"")
            .contains("\"durationMs\":");
    }

    @Test
    void logs_shouldNeverContainTheFullCpfNorTheIssuedToken() {
        call(handlerWith(ClientStatus.ACTIVE), eventWithCpf(VALID_CPF));
        call(handlerWith(ClientStatus.BLOCKED), eventWithCpf(VALID_CPF));
        call(handlerWith(ClientStatus.ACTIVE), eventWithCpf("529.982.247-24"));

        assertThat(logs()).doesNotContain("52998224725").doesNotContain("529.982.247-25")
            .doesNotContain("jwt-do-cliente-42");
    }

    @Test
    void logs_shouldBeOneJsonObjectPerLine() throws Exception {
        call(handlerWith(ClientStatus.ACTIVE), eventWithCpf(VALID_CPF));
        call(handlerWith(ClientStatus.BLOCKED), eventWithCpf(VALID_CPF));

        for (String line : logs().strip().split("\n")) {
            assertThat(JSONObjectUtils.parse(line)).containsKeys("level", "event");
        }
    }

    /** Contexto mínimo do Lambda: só o que o handler lê. */
    private static final class StubContext implements Context {
        @Override public String getAwsRequestId() { return LAMBDA_REQUEST_ID; }
        @Override public String getLogGroupName() { return "/aws/lambda/test"; }
        @Override public String getLogStreamName() { return "stream"; }
        @Override public String getFunctionName() { return "auth"; }
        @Override public String getFunctionVersion() { return "1"; }
        @Override public String getInvokedFunctionArn() { return "arn:aws:lambda:us-east-1:0:function:auth"; }
        @Override public CognitoIdentity getIdentity() { return null; }
        @Override public ClientContext getClientContext() { return null; }
        @Override public int getRemainingTimeInMillis() { return 10_000; }
        @Override public int getMemoryLimitInMB() { return 512; }
        @Override public LambdaLogger getLogger() {
            return new LambdaLogger() {
                @Override public void log(String message) { }
                @Override public void log(byte[] message) { }
            };
        }
    }
}
