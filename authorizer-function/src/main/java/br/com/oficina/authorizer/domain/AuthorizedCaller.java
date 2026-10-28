package br.com.oficina.authorizer.domain;

import java.util.Objects;
import java.util.Optional;

/**
 * Quem passou pelo authorizer. Vira o {@code context} da resposta; a aplicação continua validando o JWT
 * por conta própria, então este contexto é informativo (log de acesso do gateway), não uma credencial.
 */
public record AuthorizedCaller(String subject, Role role, Optional<Long> clientId) {

    public AuthorizedCaller {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(clientId, "clientId");
    }
}
