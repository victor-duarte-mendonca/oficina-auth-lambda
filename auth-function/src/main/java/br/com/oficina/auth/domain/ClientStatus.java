package br.com.oficina.auth.domain;

/** Situação do cliente ({@code clients.status}). Só {@code ACTIVE} autentica. */
public enum ClientStatus {
    ACTIVE,
    INACTIVE,
    BLOCKED,
    /** Valor fora do contrato do banco: nunca autentica. */
    UNKNOWN;

    public static ClientStatus fromDatabase(String value) {
        if (value == null) {
            return UNKNOWN;
        }
        try {
            return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
