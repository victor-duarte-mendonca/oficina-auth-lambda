package br.com.oficina.auth.application;

import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.Cpf;

/** Porta de saída: emite o token de acesso do cliente já autenticado. */
public interface TokenIssuerPort {

    IssuedToken issue(ClientAccount client, Cpf cpf);

    /** Token compacto (JWS) e quanto tempo ele vale. */
    record IssuedToken(String accessToken, long expiresInSeconds) {
    }
}
