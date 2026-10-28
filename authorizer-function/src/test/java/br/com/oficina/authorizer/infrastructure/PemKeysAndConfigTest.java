package br.com.oficina.authorizer.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class PemKeysAndConfigTest {

    private static String base64Der;
    private static String publicPem;
    private static String privatePem;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        base64Der = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        publicPem = "-----BEGIN PUBLIC KEY-----\n" + base64Der.replaceAll("(.{64})", "$1\n") + "\n-----END PUBLIC KEY-----\n";
        privatePem = "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()).replaceAll("(.{64})", "$1\n")
            + "\n-----END PRIVATE KEY-----\n";
    }

    // ===== PemKeys =====

    @Test
    void publicKey_shouldReadAFullPem() {
        assertThat(PemKeys.publicKey(publicPem)).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    void publicKey_shouldReadAPemWithEscapedNewlines() {
        assertThat(PemKeys.publicKey(publicPem.replace("\n", "\\n"))).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    void publicKey_shouldReadAPemWithWindowsLineEndings() {
        assertThat(PemKeys.publicKey(publicPem.replace("\n", "\r\n"))).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    void publicKey_shouldReadBareBase64() {
        assertThat(PemKeys.publicKey(base64Der)).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    void publicKey_shouldRejectGarbageWithoutEchoingTheInput() {
        assertThatThrownBy(() -> PemKeys.publicKey("isto-nao-e-uma-chave-SEGREDO123"))
            .isInstanceOf(IllegalStateException.class).hasMessageNotContaining("SEGREDO123");
    }

    /** Erro de configuração previsível: colar a chave PRIVADA onde se espera a pública. */
    @Test
    void publicKey_shouldRejectAPrivateKeyPastedByMistake() {
        assertThatThrownBy(() -> PemKeys.publicKey(privatePem))
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_PUBLIC_KEY_PEM");
    }

    // ===== AuthorizerConfig =====

    @Test
    void config_shouldApplyDefaults() {
        Map<String, String> env = new HashMap<>();
        env.put("JWT_PUBLIC_KEY_PEM", publicPem);

        AuthorizerConfig config = AuthorizerConfig.from(env::get);

        assertThat(config.issuer()).isEqualTo("oficina-api");
        assertThat(config.clockSkew()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void config_shouldReadOverrides() {
        Map<String, String> env = new HashMap<>();
        env.put("JWT_PUBLIC_KEY_PEM", publicPem);
        env.put("JWT_ISSUER", "outro");
        env.put("CLOCK_SKEW_SECONDS", "5");

        AuthorizerConfig config = AuthorizerConfig.from(env::get);

        assertThat(config.issuer()).isEqualTo("outro");
        assertThat(config.clockSkew()).isEqualTo(Duration.ofSeconds(5));
    }

    @Test
    void config_shouldFailNamingTheMissingVariable() {
        assertThatThrownBy(() -> AuthorizerConfig.from(name -> null))
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_PUBLIC_KEY_PEM");
    }

    @Test
    void config_shouldTreatABlankKeyAsMissing() {
        assertThatThrownBy(() -> AuthorizerConfig.from(name -> "JWT_PUBLIC_KEY_PEM".equals(name) ? "   " : null))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void config_shouldNeverRequireADatabaseOrAnySecret() {
        // O authorizer só precisa da chave pública: nenhuma credencial de banco entra na configuração.
        assertThat(AuthorizerConfig.class.getRecordComponents()).extracting(c -> c.getName())
            .containsExactly("publicKeyPem", "issuer", "clockSkew");
    }
}
