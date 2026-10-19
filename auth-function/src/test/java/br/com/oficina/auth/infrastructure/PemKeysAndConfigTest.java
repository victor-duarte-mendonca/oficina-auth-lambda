package br.com.oficina.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class PemKeysAndConfigTest {

    private static String base64Der;
    private static String pem;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        base64Der = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        pem = "-----BEGIN PRIVATE KEY-----\n" + base64Der.replaceAll("(.{64})", "$1\n") + "\n-----END PRIVATE KEY-----\n";
    }

    // ===== PemKeys =====

    @Test
    void privateKey_shouldReadAFullPem() {
        assertThat(PemKeys.privateKey(pem)).isInstanceOf(RSAPrivateKey.class);
    }

    @Test
    void privateKey_shouldReadAPemWithEscapedNewlines() {
        // Como chega quando o segredo passa por Terraform/variável de ambiente numa linha só.
        String escaped = pem.replace("\n", "\\n");

        assertThat(PemKeys.privateKey(escaped)).isInstanceOf(RSAPrivateKey.class);
    }

    @Test
    void privateKey_shouldReadAPemWithWindowsLineEndings() {
        // Formato dos arquivos .pem gerados e versionados no Windows (CRLF), como o da aplicação.
        assertThat(PemKeys.privateKey(pem.replace("\n", "\r\n"))).isInstanceOf(RSAPrivateKey.class);
    }

    @Test
    void privateKey_shouldReadBareBase64() {
        assertThat(PemKeys.privateKey(base64Der)).isInstanceOf(RSAPrivateKey.class);
    }

    @Test
    void privateKey_shouldRejectGarbageWithoutEchoingTheInput() {
        assertThatThrownBy(() -> PemKeys.privateKey("isto-nao-e-uma-chave-SEGREDO123"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageNotContaining("SEGREDO123");
    }

    // ===== AppConfig =====

    private static Map<String, String> fullEnvironment() {
        Map<String, String> env = new HashMap<>();
        env.put("DB_HOST", "oficina.cluster.rds.amazonaws.com");
        env.put("DB_NAME", "oficina_db");
        env.put("DB_USER", "oficina_auth_ro");
        env.put("DB_PASSWORD", "senha-do-banco-secreta");
        env.put("JWT_PRIVATE_KEY_PEM", "pem-secreto");
        return env;
    }

    @Test
    void config_shouldApplyDefaults() {
        AppConfig config = AppConfig.from(fullEnvironment()::get);

        assertThat(config.dbPort()).isEqualTo(5432);
        assertThat(config.jwtIssuer()).isEqualTo("oficina-api");
        assertThat(config.jwtTtlSeconds()).isEqualTo(3600);
    }

    @Test
    void config_shouldReadOverrides() {
        Map<String, String> env = fullEnvironment();
        env.put("DB_PORT", "5433");
        env.put("JWT_ISSUER", "outro");
        env.put("JWT_TTL_SECONDS", "60");

        AppConfig config = AppConfig.from(env::get);

        assertThat(config.dbPort()).isEqualTo(5433);
        assertThat(config.jwtIssuer()).isEqualTo("outro");
        assertThat(config.jwtTtlSeconds()).isEqualTo(60);
    }

    @Test
    void config_shouldNameEveryMissingVariableButNeverAValue() {
        Map<String, String> env = fullEnvironment();
        env.remove("DB_HOST");
        env.put("DB_PASSWORD", "  ");

        assertThatThrownBy(() -> AppConfig.from(env::get))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("DB_HOST").hasMessageContaining("DB_PASSWORD")
            .hasMessageNotContaining("pem-secreto").hasMessageNotContaining("oficina_auth_ro");
    }

    @Test
    void config_toString_shouldNeverPrintSecrets() {
        String text = AppConfig.from(fullEnvironment()::get).toString();

        assertThat(text).doesNotContain("senha-do-banco-secreta").doesNotContain("pem-secreto");
    }

    @Test
    void config_jdbcUrl_shouldRequireTlsAndUseShortTimeouts() {
        String url = AppConfig.from(fullEnvironment()::get).jdbcUrl();

        assertThat(url).startsWith("jdbc:postgresql://oficina.cluster.rds.amazonaws.com:5432/oficina_db?")
            .contains("sslmode=require").contains("connectTimeout=3").contains("socketTimeout=5");
    }
}
