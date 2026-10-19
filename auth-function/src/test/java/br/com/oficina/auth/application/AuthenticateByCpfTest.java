package br.com.oficina.auth.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.oficina.auth.application.AuthenticationResult.Granted;
import br.com.oficina.auth.application.AuthenticationResult.InvalidRequest;
import br.com.oficina.auth.application.AuthenticationResult.Unauthorized;
import br.com.oficina.auth.application.AuthenticationResult.Unauthorized.Reason;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.ClientStatus;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AuthenticateByCpfTest {

    private static final String CPF = "529.982.247-25";

    private final List<String> lookups = new ArrayList<>();

    private AuthenticateByCpf useCaseWith(Optional<ClientAccount> stored) {
        ClientLookupPort lookup = cpf -> {
            lookups.add(cpf.digits());
            return stored;
        };
        TokenIssuerPort issuer = (client, cpf) -> new TokenIssuerPort.IssuedToken("token-de-" + client.id(), 3600);
        return new AuthenticateByCpf(lookup, issuer);
    }

    @Test
    void activeClient_shouldBeGrantedAToken() {
        var result = useCaseWith(Optional.of(new ClientAccount(42, "Maria Souza", ClientStatus.ACTIVE))).execute(CPF);

        assertThat(result).isInstanceOfSatisfying(Granted.class, granted -> {
            assertThat(granted.token().accessToken()).isEqualTo("token-de-42");
            assertThat(granted.client().id()).isEqualTo(42);
            assertThat(granted.cpfMasked()).isEqualTo("529******25");
        });
        assertThat(lookups).containsExactly("52998224725");
    }

    @Test
    void unknownCpf_shouldBeUnauthorizedAsNotFound() {
        var result = useCaseWith(Optional.empty()).execute(CPF);

        assertThat(result).isEqualTo(new Unauthorized(Reason.NOT_FOUND, "529******25"));
    }

    @Test
    void blockedClient_shouldBeUnauthorizedAsBlocked() {
        var result = useCaseWith(Optional.of(new ClientAccount(1, "B", ClientStatus.BLOCKED))).execute(CPF);

        assertThat(result).isEqualTo(new Unauthorized(Reason.BLOCKED, "529******25"));
    }

    @Test
    void inactiveClient_shouldBeUnauthorizedAsInactive() {
        var result = useCaseWith(Optional.of(new ClientAccount(1, "I", ClientStatus.INACTIVE))).execute(CPF);

        assertThat(result).isEqualTo(new Unauthorized(Reason.INACTIVE, "529******25"));
    }

    @Test
    void unknownStatus_shouldNeverAuthenticate() {
        var result = useCaseWith(Optional.of(new ClientAccount(1, "U", ClientStatus.UNKNOWN))).execute(CPF);

        assertThat(result).isInstanceOf(Unauthorized.class);
    }

    @Test
    void everyDenialPath_shouldQueryTheDatabaseBeforeDeciding() {
        // O caminho de erro não pode retornar antes da consulta, ou o tempo distinguiria os casos.
        useCaseWith(Optional.empty()).execute(CPF);
        useCaseWith(Optional.of(new ClientAccount(1, "B", ClientStatus.BLOCKED))).execute(CPF);
        useCaseWith(Optional.of(new ClientAccount(1, "I", ClientStatus.INACTIVE))).execute(CPF);

        assertThat(lookups).hasSize(3);
    }

    @Test
    void invalidCpf_shouldBeRejectedWithoutTouchingTheDatabase() {
        var result = useCaseWith(Optional.empty()).execute("529.982.247-24");

        assertThat(result).isEqualTo(new InvalidRequest("CPF inválido"));
        assertThat(lookups).isEmpty();
    }

    @Test
    void missingCpf_shouldBeInvalidRequest() {
        assertThat(useCaseWith(Optional.empty()).execute(null)).isInstanceOf(InvalidRequest.class);
    }

    @Test
    void databaseFailure_shouldPropagateInsteadOfBeingHiddenAsNotFound() {
        ClientLookupPort failing = cpf -> {
            throw new IllegalStateException("banco fora");
        };
        var useCase = new AuthenticateByCpf(failing, (client, cpf) -> null);

        assertThatThrownBy(() -> useCase.execute(CPF)).isInstanceOf(IllegalStateException.class);
    }
}
