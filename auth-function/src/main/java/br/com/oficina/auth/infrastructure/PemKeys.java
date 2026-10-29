package br.com.oficina.auth.infrastructure;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/** Leitura da chave privada RSA (PKCS#8) entregue por variável de ambiente. Só em memória, nada em /tmp. */
final class PemKeys {

    private PemKeys() {
    }

    /**
     * Aceita o PEM completo, com cabeçalho e quebras de linha reais ou escapadas ({@code \n} literal,
     * comum quando o segredo passa por Terraform/variável de ambiente), e também só o Base64.
     */
    static RSAPrivateKey privateKey(String pem) {
        String base64 = pem
            .replace("\\n", "")
            .replaceAll("-----BEGIN [A-Z ]*PRIVATE KEY-----", "")
            .replaceAll("-----END [A-Z ]*PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            // Sem a causa: a mensagem original pode ecoar trechos do material da chave.
            throw new IllegalStateException("JWT_PRIVATE_KEY_PEM inválida: esperado RSA em PKCS#8");
        }
    }
}
