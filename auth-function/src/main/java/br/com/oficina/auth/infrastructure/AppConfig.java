package br.com.oficina.auth.infrastructure;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Configuração vinda das variáveis de ambiente do Lambda (spec 02 §4). Sem Secrets Manager/SSM em
 * runtime: sem NAT essas APIs públicas não são alcançáveis; os segredos entram como variáveis de
 * ambiente, criptografadas em repouso pela chave gerenciada {@code aws/lambda}.
 */
public record AppConfig(
    String dbHost,
    int dbPort,
    String dbName,
    String dbUser,
    String dbPassword,
    String jwtPrivateKeyPem,
    String jwtIssuer,
    long jwtTtlSeconds
) {

    private static final int DEFAULT_DB_PORT = 5432;
    private static final String DEFAULT_ISSUER = "oficina-api";
    private static final long DEFAULT_TTL_SECONDS = 3600;

    public static AppConfig fromEnvironment() {
        return from(System::getenv);
    }

    /** Separado de {@link #fromEnvironment()} para ser testável sem tocar o ambiente do processo. */
    static AppConfig from(Function<String, String> env) {
        List<String> missing = new ArrayList<>();
        String host = required(env, "DB_HOST", missing);
        String name = required(env, "DB_NAME", missing);
        String user = required(env, "DB_USER", missing);
        String password = required(env, "DB_PASSWORD", missing);
        String pem = required(env, "JWT_PRIVATE_KEY_PEM", missing);
        if (!missing.isEmpty()) {
            // Só os NOMES: um valor de segredo jamais entra numa mensagem de erro.
            throw new IllegalStateException("Variáveis de ambiente ausentes: " + String.join(", ", missing));
        }
        return new AppConfig(
            host,
            intOrDefault(env.apply("DB_PORT"), DEFAULT_DB_PORT),
            name,
            user,
            password,
            pem,
            orDefault(env.apply("JWT_ISSUER"), DEFAULT_ISSUER),
            longOrDefault(env.apply("JWT_TTL_SECONDS"), DEFAULT_TTL_SECONDS));
    }

    /**
     * TLS obrigatório ({@code sslmode=require}): o RDS roda com {@code rds.force_ssl=1}, então
     * conexão sem TLS é recusada. Timeouts curtos para que um banco indisponível vire 500 rápido em
     * vez de consumir os 10 s do Lambda.
     */
    public String jdbcUrl() {
        return "jdbc:postgresql://" + dbHost + ":" + dbPort + "/" + dbName
            + "?sslmode=require&connectTimeout=3&socketTimeout=5&tcpKeepAlive=true"
            + "&ApplicationName=oficina-auth-lambda";
    }

    /** Nunca imprime segredos. */
    @Override
    public String toString() {
        return "AppConfig[dbHost=" + dbHost + ", dbPort=" + dbPort + ", dbName=" + dbName
            + ", dbUser=" + dbUser + ", jwtIssuer=" + jwtIssuer + ", jwtTtlSeconds=" + jwtTtlSeconds + "]";
    }

    private static String required(Function<String, String> env, String name, List<String> missing) {
        String value = env.apply(name);
        if (value == null || value.isBlank()) {
            missing.add(name);
            return null;
        }
        return value;
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static int intOrDefault(String value, int fallback) {
        return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
    }

    private static long longOrDefault(String value, long fallback) {
        return value == null || value.isBlank() ? fallback : Long.parseLong(value.trim());
    }
}
