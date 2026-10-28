package br.com.oficina.authorizer.infrastructure;

import br.com.oficina.authorizer.application.TokenVerifierPort;
import br.com.oficina.authorizer.domain.DenialReason;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Verifica o JWT com a chave <b>pública</b> (RS256), o emissor e a validade. A ordem importa: a
 * assinatura é conferida <b>antes</b> de qualquer claim ser considerada, e o algoritmo é fixado em
 * RS256 — recusar {@code none} e HS256 é o que impede o ataque clássico de confusão de algoritmo
 * (assinar com HMAC usando a chave pública como segredo).
 */
public final class JwtVerifier implements TokenVerifierPort {

    private final RSASSAVerifier signatureVerifier;
    private final String issuer;
    private final Duration clockSkew;
    private final Clock clock;

    public JwtVerifier(RSAPublicKey publicKey, String issuer, Duration clockSkew, Clock clock) {
        this.signatureVerifier = new RSASSAVerifier(publicKey);
        this.issuer = issuer;
        this.clockSkew = clockSkew;
        this.clock = clock;
    }

    @Override
    public VerifiedToken verify(String token) {
        SignedJWT jwt = parse(token);
        requireRs256(jwt);
        requireValidSignature(jwt);
        JWTClaimsSet claims = claimsOf(jwt);

        requireIssuer(claims);
        requireWithinValidity(claims);
        String subject = requireSubject(claims);
        return new VerifiedToken(subject, groupsOf(claims), clientIdOf(claims));
    }

    private static SignedJWT parse(String token) {
        try {
            return SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new TokenRejectedException(DenialReason.MALFORMED_TOKEN);
        }
    }

    private static void requireRs256(SignedJWT jwt) {
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new TokenRejectedException(DenialReason.UNSUPPORTED_ALGORITHM);
        }
    }

    private void requireValidSignature(SignedJWT jwt) {
        try {
            if (!jwt.verify(signatureVerifier)) {
                throw new TokenRejectedException(DenialReason.BAD_SIGNATURE);
            }
        } catch (JOSEException e) {
            throw new TokenRejectedException(DenialReason.BAD_SIGNATURE);
        }
    }

    private static JWTClaimsSet claimsOf(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new TokenRejectedException(DenialReason.MALFORMED_TOKEN);
        }
    }

    private void requireIssuer(JWTClaimsSet claims) {
        if (!issuer.equals(claims.getIssuer())) {
            throw new TokenRejectedException(DenialReason.BAD_ISSUER);
        }
    }

    private void requireWithinValidity(JWTClaimsSet claims) {
        Instant now = clock.instant();
        Date expiration = claims.getExpirationTime();
        // Sem exp o token valeria para sempre: é recusado como expirado.
        if (expiration == null || now.isAfter(expiration.toInstant().plus(clockSkew))) {
            throw new TokenRejectedException(DenialReason.EXPIRED);
        }
        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && now.isBefore(notBefore.toInstant().minus(clockSkew))) {
            throw new TokenRejectedException(DenialReason.NOT_YET_VALID);
        }
    }

    private static String requireSubject(JWTClaimsSet claims) {
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new TokenRejectedException(DenialReason.MISSING_SUBJECT);
        }
        return subject;
    }

    private static List<String> groupsOf(JWTClaimsSet claims) {
        try {
            List<String> groups = claims.getStringListClaim("groups");
            return groups == null ? List.of() : groups;
        } catch (ParseException e) {
            // "groups" com tipo errado: sem papel utilizável.
            return List.of();
        }
    }

    private static Optional<Long> clientIdOf(JWTClaimsSet claims) {
        Object raw = claims.getClaim("clientId");
        if (raw instanceof Number number) {
            return Optional.of(number.longValue());
        }
        return Optional.empty();
    }
}
