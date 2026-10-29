package br.com.oficina.auth.domain;

import java.util.Objects;

/**
 * O que a função sabe de um cliente: identidade, nome e situação. É tudo o que o papel
 * {@code oficina_auth_ro} consegue ler — e-mail e telefone ficam de fora no próprio {@code GRANT}.
 */
public record ClientAccount(long id, String name, ClientStatus status) {

    public ClientAccount {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(status, "status");
    }

    public boolean isActive() {
        return status == ClientStatus.ACTIVE;
    }

    /**
     * Nome para exibição na resposta: primeiro nome e inicial do último sobrenome ("Maria S."). A
     * resposta de autenticação não precisa expor o nome completo.
     */
    public String displayName() {
        String[] parts = name.trim().split("\\s+");
        if (parts.length == 1) {
            return parts[0];
        }
        String lastName = parts[parts.length - 1];
        return parts[0] + " " + lastName.substring(0, 1).toUpperCase(java.util.Locale.ROOT) + ".";
    }
}
