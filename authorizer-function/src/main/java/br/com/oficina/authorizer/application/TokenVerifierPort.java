package br.com.oficina.authorizer.application;

import br.com.oficina.authorizer.domain.DenialReason;
import java.util.List;
import java.util.Optional;

/** Porta de saída: confere assinatura e validade de um JWT. */
public interface TokenVerifierPort {

    /**
     * @throws TokenRejectedException se o token não for aceito, com o motivo para o log
     */
    VerifiedToken verify(String token);

    /** Claims já conferidas: a assinatura bate e o token está dentro da validade. */
    record VerifiedToken(String subject, List<String> groups, Optional<Long> clientId) {
    }

    final class TokenRejectedException extends RuntimeException {

        private final DenialReason reason;

        public TokenRejectedException(DenialReason reason) {
            // Sem mensagem com conteúdo do token e sem stack trace: é fluxo normal, não erro.
            super(reason.name(), null, false, false);
            this.reason = reason;
        }

        public DenialReason reason() {
            return reason;
        }
    }
}
