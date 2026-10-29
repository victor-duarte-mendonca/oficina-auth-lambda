package br.com.oficina.authorizer.infrastructure;

import java.time.Duration;
import java.util.function.Function;

/**
 * Configuração das variáveis de ambiente. A única entrada sensível ao funcionamento é a chave
 * <b>pública</b> — que não é segredo. O authorizer não recebe credencial de banco, rede nem segredo
 * algum: essa ausência é o controle que o mantém sem acesso ao RDS (spec 03 §7).
 */
public record AuthorizerConfig(String publicKeyPem, String issuer, Duration clockSkew) {

    private static final String DEFAULT_ISSUER = "oficina-api";
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 30;

    public static AuthorizerConfig fromEnvironment() {
        return from(System::getenv);
    }

    /** Separado de {@link #fromEnvironment()} para ser testável sem tocar o ambiente do processo. */
    static AuthorizerConfig from(Function<String, String> env) {
        String publicKey = env.apply("JWT_PUBLIC_KEY_PEM");
        if (publicKey == null || publicKey.isBlank()) {
            throw new IllegalStateException("Variável de ambiente ausente: JWT_PUBLIC_KEY_PEM");
        }
        return new AuthorizerConfig(
            publicKey,
            orDefault(env.apply("JWT_ISSUER"), DEFAULT_ISSUER),
            Duration.ofSeconds(longOrDefault(env.apply("CLOCK_SKEW_SECONDS"), DEFAULT_CLOCK_SKEW_SECONDS)));
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static long longOrDefault(String value, long fallback) {
        return value == null || value.isBlank() ? fallback : Long.parseLong(value.trim());
    }
}
