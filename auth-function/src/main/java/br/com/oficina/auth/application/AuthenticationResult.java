package br.com.oficina.auth.application;

import br.com.oficina.auth.domain.ClientAccount;

/**
 * Desfecho da autenticação. O adapter HTTP traduz cada caso em status e corpo. O CPF aparece só
 * mascarado, e só para o log do operador.
 */
public sealed interface AuthenticationResult {

    record Granted(TokenIssuerPort.IssuedToken token, ClientAccount client, String cpfMasked)
        implements AuthenticationResult {
    }

    /** CPF ausente, malformado ou com dígito verificador errado (400). */
    record InvalidRequest(String message) implements AuthenticationResult {
    }

    /**
     * Cliente inexistente, inativo ou bloqueado (401). O motivo existe só para o log do operador: na
     * resposta os três casos são byte a byte idênticos, senão o endpoint viraria um validador de
     * "este CPF é cliente da oficina?".
     */
    record Unauthorized(Reason reason, String cpfMasked) implements AuthenticationResult {

        public enum Reason { NOT_FOUND, INACTIVE, BLOCKED }
    }
}
