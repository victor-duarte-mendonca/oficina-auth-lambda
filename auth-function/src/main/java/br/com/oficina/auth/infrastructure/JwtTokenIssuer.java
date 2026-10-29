package br.com.oficina.auth.infrastructure;

import br.com.oficina.auth.application.TokenIssuerPort;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.Cpf;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Emite o JWT do cliente: RS256 com a <b>mesma chave privada e o mesmo {@code iss}</b> que a aplicação
 * usa. Por isso a aplicação valida este token sem nenhuma configuração nova
 * ({@code mp.jwt.verify.publickey.location} já aponta para a chave pública correspondente).
 */
public final class JwtTokenIssuer implements TokenIssuerPort {

    static final String CLIENT_GROUP = "CLIENT";

    private final RSASSASigner signer;
    private final String issuer;
    private final long ttlSeconds;
    private final Clock clock;

    public JwtTokenIssuer(RSAPrivateKey privateKey, String issuer, long ttlSeconds, Clock clock) {
        this.signer = new RSASSASigner(privateKey);
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    @Override
    public IssuedToken issue(ClientAccount client, Cpf cpf) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(String.valueOf(client.id()))
            .claim("upn", String.valueOf(client.id()))
            .claim("groups", List.of(CLIENT_GROUP))
            .claim("clientId", client.id())
            // Mascarado: o token trafega em logs de gateway e ferramentas de observabilidade.
            .claim("cpf", cpf.masked())
            // Permite revogação futura (denylist) sem quebrar o contrato; hoje não há revogação.
            .jwtID(UUID.randomUUID().toString())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
            .build();

        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            // Sem a causa na mensagem: evita ecoar detalhes do material criptográfico.
            throw new TokenSigningException("Falha ao assinar o token", e);
        }
        return new IssuedToken(jwt.serialize(), ttlSeconds);
    }

    /** Falha de assinatura (500 para o chamador). */
    public static final class TokenSigningException extends RuntimeException {
        TokenSigningException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
