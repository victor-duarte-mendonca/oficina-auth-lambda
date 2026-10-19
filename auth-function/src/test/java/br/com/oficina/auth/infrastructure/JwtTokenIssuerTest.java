package br.com.oficina.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.oficina.auth.application.TokenIssuerPort.IssuedToken;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.ClientStatus;
import br.com.oficina.auth.domain.Cpf;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class JwtTokenIssuerTest {

    private static final Instant NOW = Instant.parse("2026-10-19T12:00:00Z");

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;

    private final JwtTokenIssuer issuer =
        new JwtTokenIssuer(privateKey, "oficina-api", 3600, Clock.fixed(NOW, ZoneOffset.UTC));
    private final ClientAccount client = new ClientAccount(42, "Maria Souza", ClientStatus.ACTIVE);
    private final Cpf cpf = Cpf.parse("529.982.247-25");

    @BeforeAll
    static void generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
    }

    @Test
    void issue_shouldSignWithRs256VerifiableByThePublicKey() throws Exception {
        SignedJWT jwt = SignedJWT.parse(issuer.issue(client, cpf).accessToken());

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();
    }

    @Test
    void issue_shouldRejectATokenVerifiedWithAnotherKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPublicKey otherKey = (RSAPublicKey) generator.generateKeyPair().getPublic();

        SignedJWT jwt = SignedJWT.parse(issuer.issue(client, cpf).accessToken());

        assertThat(jwt.verify(new RSASSAVerifier(otherKey))).isFalse();
    }

    @Test
    void issue_shouldCarryTheContractClaims() throws Exception {
        JWTClaimsSet claims = claimsOf(issuer.issue(client, cpf));

        assertThat(claims.getIssuer()).isEqualTo("oficina-api");
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getStringClaim("upn")).isEqualTo("42");
        assertThat(claims.getStringListClaim("groups")).containsExactly("CLIENT");
        assertThat(claims.getLongClaim("clientId")).isEqualTo(42L);
        assertThat(claims.getJWTID()).isNotBlank();
    }

    @Test
    void issue_shouldMaskTheCpfInTheClaimAndNeverCarryTheFullOne() throws Exception {
        IssuedToken token = issuer.issue(client, cpf);

        assertThat(claimsOf(token).getStringClaim("cpf")).isEqualTo("529******25");
        // O token inteiro (payload em Base64) também não pode conter o CPF completo em claro.
        assertThat(new String(java.util.Base64.getUrlDecoder().decode(token.accessToken().split("\\.")[1])))
            .doesNotContain("52998224725");
    }

    @Test
    void issue_shouldExpireAfterTheConfiguredTtl() throws Exception {
        IssuedToken token = issuer.issue(client, cpf);
        JWTClaimsSet claims = claimsOf(token);

        assertThat(token.expiresInSeconds()).isEqualTo(3600);
        assertThat(claims.getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(claims.getExpirationTime().toInstant()).isEqualTo(NOW.plusSeconds(3600));
    }

    @Test
    void issue_shouldGiveEachTokenAUniqueJti() throws Exception {
        assertThat(claimsOf(issuer.issue(client, cpf)).getJWTID())
            .isNotEqualTo(claimsOf(issuer.issue(client, cpf)).getJWTID());
    }

    private static JWTClaimsSet claimsOf(IssuedToken token) throws ParseException {
        return SignedJWT.parse(token.accessToken()).getJWTClaimsSet();
    }
}
