package br.com.oficina.authorizer.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.oficina.authorizer.application.TokenVerifierPort.TokenRejectedException;
import br.com.oficina.authorizer.application.TokenVerifierPort.VerifiedToken;
import br.com.oficina.authorizer.domain.DenialReason;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * O núcleo de segurança do authorizer. Cobre os ataques clássicos contra verificação de JWT: algoritmo
 * {@code none}, confusão de algoritmo (HS256 com a chave pública como segredo), troca de algoritmo,
 * chave embutida no header, payload adulterado, expiração, {@code nbf} e emissor.
 */
class JwtVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-28T12:00:00Z");
    private static final String ISSUER = "oficina-api";

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;
    private static RSAPrivateKey attackerKey;

    private final JwtVerifier verifier =
        new JwtVerifier(publicKey, ISSUER, Duration.ofSeconds(30), Clock.fixed(NOW, ZoneOffset.UTC));

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
        attackerKey = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
    }

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject("42")
            .claim("groups", List.of("CLIENT"))
            .claim("clientId", 42L)
            .issueTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plusSeconds(3600)));
    }

    private static String sign(JWTClaimsSet claims, RSAPrivateKey key, JWSAlgorithm algorithm) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String valid() throws JOSEException {
        return sign(validClaims().build(), privateKey, JWSAlgorithm.RS256);
    }

    private void assertRejectedWith(String token, DenialReason expected) {
        assertThatThrownBy(() -> verifier.verify(token))
            .isInstanceOfSatisfying(TokenRejectedException.class, e -> assertThat(e.reason()).isEqualTo(expected));
    }

    // ===== caminho feliz =====

    @Test
    void validToken_shouldBeAcceptedWithItsClaims() throws Exception {
        VerifiedToken verified = verifier.verify(valid());

        assertThat(verified.subject()).isEqualTo("42");
        assertThat(verified.groups()).containsExactly("CLIENT");
        assertThat(verified.clientId()).contains(42L);
    }

    @Test
    void tokenWithoutClientId_shouldStillBeAccepted() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).subject("admin")
            .claim("groups", List.of("ADMIN")).expirationTime(Date.from(NOW.plusSeconds(60))).build();

        VerifiedToken verified = verifier.verify(sign(claims, privateKey, JWSAlgorithm.RS256));

        assertThat(verified.clientId()).isEmpty();
        assertThat(verified.groups()).containsExactly("ADMIN");
    }

    // ===== assinatura =====

    @Test
    void tokenSignedByAnotherKey_shouldBeRejected() throws Exception {
        assertRejectedWith(sign(validClaims().build(), attackerKey, JWSAlgorithm.RS256), DenialReason.BAD_SIGNATURE);
    }

    @Test
    void tamperedPayload_shouldBeRejected() throws Exception {
        // Troca o payload por um com papel ADMIN, mantendo a assinatura original.
        String[] parts = valid().split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            validClaims().claim("groups", List.of("ADMIN")).build().toString().getBytes());

        assertRejectedWith(parts[0] + "." + forgedPayload + "." + parts[2], DenialReason.BAD_SIGNATURE);
    }

    @Test
    void truncatedSignature_shouldBeRejected() throws Exception {
        String token = valid();

        assertThatThrownBy(() -> verifier.verify(token.substring(0, token.length() - 10)))
            .isInstanceOf(TokenRejectedException.class);
    }

    // ===== ataques de algoritmo =====

    @Test
    void algNone_shouldBeRejected() {
        String unsecured = new PlainJWT(validClaims().build()).serialize();

        assertThatThrownBy(() -> verifier.verify(unsecured))
            .isInstanceOfSatisfying(TokenRejectedException.class, e ->
                assertThat(e.reason()).isIn(DenialReason.MALFORMED_TOKEN, DenialReason.UNSUPPORTED_ALGORITHM));
    }

    /** O ataque clássico: assinar com HMAC usando a chave PÚBLICA (conhecida) como segredo. */
    @Test
    void hs256SignedWithThePublicKeyAsSecret_shouldBeRejected() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), validClaims().build());
        JWSSigner hmac = new MACSigner(publicKey.getEncoded());
        jwt.sign(hmac);

        assertRejectedWith(jwt.serialize(), DenialReason.UNSUPPORTED_ALGORITHM);
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS384", "RS512", "PS256"})
    void anyAlgorithmOtherThanRs256_shouldBeRejectedEvenWithTheRightKey(String algorithm) throws Exception {
        assertRejectedWith(sign(validClaims().build(), privateKey, JWSAlgorithm.parse(algorithm)),
            DenialReason.UNSUPPORTED_ALGORITHM);
    }

    /** Uma chave embutida no header ({@code jwk}) NUNCA é usada: só a chave configurada verifica. */
    @Test
    void tokenCarryingTheAttackersOwnKeyInTheHeader_shouldBeRejected() throws Exception {
        RSAKey attackerJwk = new RSAKey.Builder((RSAPublicKey) publicKeyOf(attackerKey)).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(attackerJwk).build(),
            validClaims().build());
        jwt.sign(new RSASSASigner(attackerKey));

        assertRejectedWith(jwt.serialize(), DenialReason.BAD_SIGNATURE);
    }

    @Test
    void unknownCriticalHeader_shouldBeRejected() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).criticalParams(Set.of("exp-x"))
            .customParam("exp-x", "1").build();
        SignedJWT jwt = new SignedJWT(header, validClaims().build());
        jwt.sign(new RSASSASigner(privateKey, true));

        assertThatThrownBy(() -> verifier.verify(jwt.serialize())).isInstanceOf(TokenRejectedException.class);
    }

    // ===== validade =====

    @Test
    void expiredToken_shouldBeRejected() throws Exception {
        JWTClaimsSet claims = validClaims().expirationTime(Date.from(NOW.minusSeconds(120))).build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.EXPIRED);
    }

    @Test
    void tokenExpiredWithinTheClockSkew_shouldStillBeAccepted() throws Exception {
        JWTClaimsSet claims = validClaims().expirationTime(Date.from(NOW.minusSeconds(10))).build();

        assertThat(verifier.verify(sign(claims, privateKey, JWSAlgorithm.RS256)).subject()).isEqualTo("42");
    }

    @Test
    void tokenWithoutExpiration_shouldBeRejectedBecauseItWouldNeverExpire() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).subject("42")
            .claim("groups", List.of("CLIENT")).build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.EXPIRED);
    }

    @Test
    void tokenNotYetValid_shouldBeRejected() throws Exception {
        JWTClaimsSet claims = validClaims().notBeforeTime(Date.from(NOW.plusSeconds(600))).build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.NOT_YET_VALID);
    }

    // ===== claims =====

    @Test
    void wrongIssuer_shouldBeRejected() throws Exception {
        JWTClaimsSet claims = validClaims().issuer("outro-emissor").build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.BAD_ISSUER);
    }

    @Test
    void missingIssuer_shouldBeRejected() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("42").claim("groups", List.of("CLIENT"))
            .expirationTime(Date.from(NOW.plusSeconds(60))).build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.BAD_ISSUER);
    }

    @Test
    void missingSubject_shouldBeRejected() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).claim("groups", List.of("CLIENT"))
            .expirationTime(Date.from(NOW.plusSeconds(60))).build();

        assertRejectedWith(sign(claims, privateKey, JWSAlgorithm.RS256), DenialReason.MISSING_SUBJECT);
    }

    @Test
    void groupsMissingOrOfTheWrongType_shouldYieldNoGroups() throws Exception {
        JWTClaimsSet missing = new JWTClaimsSet.Builder().issuer(ISSUER).subject("42")
            .expirationTime(Date.from(NOW.plusSeconds(60))).build();
        JWTClaimsSet wrongType = validClaims().claim("groups", "ADMIN").build();

        assertThat(verifier.verify(sign(missing, privateKey, JWSAlgorithm.RS256)).groups()).isEmpty();
        assertThat(verifier.verify(sign(wrongType, privateKey, JWSAlgorithm.RS256)).groups()).isEmpty();
    }

    @Test
    void clientIdOfTheWrongType_shouldBeIgnored() throws Exception {
        JWTClaimsSet claims = validClaims().claim("clientId", "quarenta-e-dois").build();

        assertThat(verifier.verify(sign(claims, privateKey, JWSAlgorithm.RS256)).clientId()).isEmpty();
    }

    // ===== lixo =====

    @ParameterizedTest
    @ValueSource(strings = {"", "not.a.jwt", "a.b", "a.b.c.d.e", "....", "eyJhbGciOiJSUzI1NiJ9.e30."})
    void garbage_shouldBeRejectedAsMalformed(String garbage) {
        assertThatThrownBy(() -> verifier.verify(garbage)).isInstanceOf(TokenRejectedException.class);
    }

    @Test
    void rejection_shouldNeverCarryTheTokenInItsMessageOrStack() throws Exception {
        String token = sign(validClaims().build(), attackerKey, JWSAlgorithm.RS256);

        assertThatThrownBy(() -> verifier.verify(token))
            .hasMessage("BAD_SIGNATURE").hasMessageNotContaining(token.substring(0, 20))
            .satisfies(e -> assertThat(e.getStackTrace()).isEmpty());
    }

    private static RSAPublicKey publicKeyOf(RSAPrivateKey key) throws Exception {
        java.security.interfaces.RSAPrivateCrtKey crt = (java.security.interfaces.RSAPrivateCrtKey) key;
        return (RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(
            new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
    }
}
