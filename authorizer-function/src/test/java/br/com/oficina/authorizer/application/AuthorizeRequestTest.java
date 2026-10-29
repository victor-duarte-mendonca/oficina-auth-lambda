package br.com.oficina.authorizer.application;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.oficina.authorizer.application.AuthorizationDecision.Allowed;
import br.com.oficina.authorizer.application.AuthorizationDecision.Denied;
import br.com.oficina.authorizer.application.TokenVerifierPort.TokenRejectedException;
import br.com.oficina.authorizer.application.TokenVerifierPort.VerifiedToken;
import br.com.oficina.authorizer.domain.DenialReason;
import br.com.oficina.authorizer.domain.Role;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class AuthorizeRequestTest {

    private final List<String> verifiedTokens = new ArrayList<>();

    private AuthorizeRequest withGroups(List<String> groups, Optional<Long> clientId) {
        return new AuthorizeRequest(token -> {
            verifiedTokens.add(token);
            return new VerifiedToken("42", groups, clientId);
        });
    }

    private static AuthorizeRequest rejecting(DenialReason reason) {
        return new AuthorizeRequest(token -> {
            throw new TokenRejectedException(reason);
        });
    }

    // ===== header =====

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void missingHeader_shouldBeDeniedWithoutCallingTheVerifier(String header) {
        var useCase = withGroups(List.of("CLIENT"), Optional.empty());

        assertThat(useCase.execute(header)).isEqualTo(new Denied(DenialReason.MISSING_HEADER));
        assertThat(verifiedTokens).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic dXNlcjpwYXNz", "tokenSemEsquema", "Bearer", "Bearer ", "Bearer a b", "Bearer a\tb", "Token abc"})
    void notABearerHeader_shouldBeDeniedAsMalformed(String header) {
        var useCase = withGroups(List.of("CLIENT"), Optional.empty());

        assertThat(useCase.execute(header)).isEqualTo(new Denied(DenialReason.MALFORMED_HEADER));
        assertThat(verifiedTokens).isEmpty();
    }

    @Test
    void absurdlyLargeToken_shouldBeDeniedBeforeParsing() {
        var useCase = withGroups(List.of("CLIENT"), Optional.empty());

        assertThat(useCase.execute("Bearer " + "a".repeat(9 * 1024))).isEqualTo(new Denied(DenialReason.MALFORMED_HEADER));
        assertThat(verifiedTokens).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer abc.def.ghi", "bearer abc.def.ghi", "BEARER abc.def.ghi", "  Bearer abc.def.ghi  "})
    void bearerScheme_shouldBeCaseInsensitiveAndTrimmed(String header) {
        var useCase = withGroups(List.of("CLIENT"), Optional.empty());

        assertThat(useCase.execute(header)).isInstanceOf(Allowed.class);
        assertThat(verifiedTokens).containsExactly("abc.def.ghi");
    }

    // ===== papéis =====

    @Test
    void clientToken_shouldBeAllowedWithTheClientId() {
        var decision = withGroups(List.of("CLIENT"), Optional.of(42L)).execute("Bearer t");

        assertThat(decision).isInstanceOfSatisfying(Allowed.class, allowed -> {
            assertThat(allowed.caller().role()).isEqualTo(Role.CLIENT);
            assertThat(allowed.caller().subject()).isEqualTo("42");
            assertThat(allowed.caller().clientId()).contains(42L);
        });
    }

    @Test
    void severalGroups_shouldPickTheHighestPrecedence() {
        var decision = withGroups(List.of("CLIENT", "MECHANIC", "ADMIN"), Optional.empty()).execute("Bearer t");

        assertThat(decision).isInstanceOfSatisfying(Allowed.class,
            allowed -> assertThat(allowed.caller().role()).isEqualTo(Role.ADMIN));
    }

    @Test
    void mechanicToken_shouldBeAllowed() {
        var decision = withGroups(List.of("MECHANIC"), Optional.empty()).execute("Bearer t");

        assertThat(decision).isInstanceOfSatisfying(Allowed.class,
            allowed -> assertThat(allowed.caller().role()).isEqualTo(Role.MECHANIC));
    }

    @Test
    void tokenWithoutAKnownRole_shouldBeDenied() {
        assertThat(withGroups(List.of("SUPERUSER", "root"), Optional.empty()).execute("Bearer t"))
            .isEqualTo(new Denied(DenialReason.UNKNOWN_ROLE));
        assertThat(withGroups(List.of(), Optional.empty()).execute("Bearer t"))
            .isEqualTo(new Denied(DenialReason.UNKNOWN_ROLE));
    }

    @Test
    void roleNames_shouldBeMatchedExactlyAndCaseSensitively() {
        assertThat(withGroups(List.of("admin", "Client"), Optional.empty()).execute("Bearer t"))
            .isEqualTo(new Denied(DenialReason.UNKNOWN_ROLE));
    }

    // ===== falhas =====

    @ParameterizedTest
    @ValueSource(strings = {"BAD_SIGNATURE", "EXPIRED", "BAD_ISSUER", "NOT_YET_VALID", "UNSUPPORTED_ALGORITHM"})
    void aRejectedToken_shouldBeDeniedWithTheVerifiersReason(String reason) {
        DenialReason expected = DenialReason.valueOf(reason);

        assertThat(rejecting(expected).execute("Bearer t")).isEqualTo(new Denied(expected));
    }

    /** Falhar fechado: um erro inesperado do verificador nunca pode virar autorização. */
    @Test
    void anUnexpectedVerifierFailure_shouldFailClosed() {
        var useCase = new AuthorizeRequest(token -> {
            throw new IllegalStateException("boom");
        });

        assertThat(useCase.execute("Bearer t")).isInstanceOf(Denied.class);
    }
}
