package br.com.oficina.authorizer.application;

import br.com.oficina.authorizer.application.AuthorizationDecision.Allowed;
import br.com.oficina.authorizer.application.AuthorizationDecision.Denied;
import br.com.oficina.authorizer.application.TokenVerifierPort.TokenRejectedException;
import br.com.oficina.authorizer.application.TokenVerifierPort.VerifiedToken;
import br.com.oficina.authorizer.domain.AuthorizedCaller;
import br.com.oficina.authorizer.domain.DenialReason;
import br.com.oficina.authorizer.domain.Role;
import java.util.Locale;
import java.util.Optional;

/**
 * Caso de uso: decide se uma requisição passa pelo gateway. Um token ausente, malformado, expirado ou
 * forjado <b>nunca chega ao cluster</b> — a EC2 não gasta CPU com tráfego ilegítimo.
 *
 * <p>Nunca lança: qualquer falha inesperada vira recusa. O authorizer falhando fechado é o comportamento
 * seguro; falhar aberto deixaria passar tudo.</p>
 */
public final class AuthorizeRequest {

    private static final String BEARER = "bearer ";
    /** Um JWT de verdade tem poucas centenas de bytes; recusar o absurdo antes de parsear. */
    private static final int MAX_TOKEN_LENGTH = 8 * 1024;

    private final TokenVerifierPort verifier;

    public AuthorizeRequest(TokenVerifierPort verifier) {
        this.verifier = verifier;
    }

    public AuthorizationDecision execute(String authorizationHeader) {
        Optional<String> token;
        try {
            token = extractBearerToken(authorizationHeader);
        } catch (HeaderRejectedException e) {
            return new Denied(e.reason);
        }
        if (token.isEmpty()) {
            return new Denied(DenialReason.MISSING_HEADER);
        }
        try {
            return decide(verifier.verify(token.get()));
        } catch (TokenRejectedException e) {
            return new Denied(e.reason());
        } catch (RuntimeException e) {
            // Falha inesperada do verificador: recusa (fail closed). O tipo vai ao log pelo chamador.
            return new Denied(DenialReason.MALFORMED_TOKEN);
        }
    }

    private static AuthorizationDecision decide(VerifiedToken verified) {
        Optional<Role> role = Role.highestOf(verified.groups());
        if (role.isEmpty()) {
            return new Denied(DenialReason.UNKNOWN_ROLE);
        }
        return new Allowed(new AuthorizedCaller(verified.subject(), role.get(), verified.clientId()));
    }

    private static Optional<String> extractBearerToken(String header) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        String trimmed = header.strip();
        if (!trimmed.toLowerCase(Locale.ROOT).startsWith(BEARER)) {
            throw new HeaderRejectedException(DenialReason.MALFORMED_HEADER);
        }
        String token = trimmed.substring(BEARER.length()).strip();
        if (token.isEmpty() || token.length() > MAX_TOKEN_LENGTH || token.chars().anyMatch(Character::isWhitespace)) {
            throw new HeaderRejectedException(DenialReason.MALFORMED_HEADER);
        }
        return Optional.of(token);
    }

    private static final class HeaderRejectedException extends RuntimeException {
        private final DenialReason reason;

        HeaderRejectedException(DenialReason reason) {
            super(reason.name(), null, false, false);
            this.reason = reason;
        }
    }
}
