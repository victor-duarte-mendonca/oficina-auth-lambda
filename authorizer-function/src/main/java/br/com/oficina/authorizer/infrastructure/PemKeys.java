package br.com.oficina.authorizer.infrastructure;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Leitura da chave pública RSA (X.509 / SubjectPublicKeyInfo) entregue por variável de ambiente. */
final class PemKeys {

    private PemKeys() {
    }

    /**
     * Aceita o PEM completo, com quebras de linha reais, escapadas ({@code \n} literal) ou do Windows
     * (CRLF), e também só o Base64.
     */
    static RSAPublicKey publicKey(String pem) {
        String base64 = pem
            .replace("\\n", "")
            .replaceAll("-----BEGIN [A-Z ]*PUBLIC KEY-----", "")
            .replaceAll("-----END [A-Z ]*PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("JWT_PUBLIC_KEY_PEM inválida: esperado RSA em X.509 (BEGIN PUBLIC KEY)");
        }
    }
}
