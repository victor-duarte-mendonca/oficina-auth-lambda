package br.com.oficina.authorizer.infrastructure;

import br.com.oficina.authorizer.application.AuthorizeRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Date;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Monta as dependências uma vez por ambiente de execução, na inicialização — a fase capturada pelo
 * snapshot do SnapStart. Aqui não há conexão a preservar (sem banco, sem rede): o que entra no snapshot é
 * a chave pública lida e as classes de criptografia já carregadas.
 */
final class Composition {

    /** Holder idiom: inicialização preguiçosa e thread-safe, sem sincronização no caminho quente. */
    private static final class Holder {
        static final Composition INSTANCE = new Composition();
    }

    private final StructuredLogger logger;
    private final AuthorizeRequest authorize;

    private Composition() {
        AuthorizerConfig config = AuthorizerConfig.fromEnvironment();
        this.logger = new StructuredLogger(System.out);
        JwtVerifier verifier = new JwtVerifier(
            PemKeys.publicKey(config.publicKeyPem()), config.issuer(), config.clockSkew(), Clock.systemUTC());
        this.authorize = new AuthorizeRequest(verifier);
        SnapStartHooks.register(Composition::prime);
    }

    static AuthorizeRequest authorize() {
        return Holder.INSTANCE.authorize;
    }

    static StructuredLogger logger() {
        return Holder.INSTANCE.logger;
    }

    /**
     * Aquece, antes do checkpoint, o caminho de verificação RS256 (carrega e inicializa as classes de
     * criptografia) com um par de chaves efêmero e um token descartável. Não usa a chave real nem produz
     * nada que sobre no snapshot.
     */
    private static void prime() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder()
                .issuer("warmup").subject("warmup").claim("groups", java.util.List.of("CLIENT"))
                .expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
            jwt.sign(new RSASSASigner((RSAPrivateKey) pair.getPrivate()));
            new JwtVerifier((RSAPublicKey) pair.getPublic(), "warmup", java.time.Duration.ofSeconds(30),
                Clock.systemUTC()).verify(jwt.serialize());
        } catch (NoSuchAlgorithmException | JOSEException e) {
            // Otimização apenas: falhar aqui não pode impedir a publicação da versão.
        }
    }
}
