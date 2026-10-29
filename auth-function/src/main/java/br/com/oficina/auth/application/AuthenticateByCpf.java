package br.com.oficina.auth.application;

import br.com.oficina.auth.application.AuthenticationResult.Granted;
import br.com.oficina.auth.application.AuthenticationResult.InvalidRequest;
import br.com.oficina.auth.application.AuthenticationResult.Unauthorized;
import br.com.oficina.auth.application.AuthenticationResult.Unauthorized.Reason;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.Cpf;
import br.com.oficina.auth.domain.InvalidCpfException;
import java.util.Optional;

/**
 * Caso de uso: autentica um cliente pelo CPF e emite o token.
 *
 * <p>O caminho de recusa <b>não retorna antes da consulta</b>: "não existe", "inativo" e "bloqueado"
 * fazem o mesmo trabalho (uma consulta ao banco) antes de decidir, para o tempo de resposta não
 * distinguir os casos.</p>
 */
public final class AuthenticateByCpf {

    private final ClientLookupPort clients;
    private final TokenIssuerPort tokens;

    public AuthenticateByCpf(ClientLookupPort clients, TokenIssuerPort tokens) {
        this.clients = clients;
        this.tokens = tokens;
    }

    public AuthenticationResult execute(String rawCpf) {
        Cpf cpf;
        try {
            cpf = Cpf.parse(rawCpf);
        } catch (InvalidCpfException e) {
            return new InvalidRequest("CPF inválido");
        }

        Optional<ClientAccount> found = clients.findByCpf(cpf);
        if (found.isEmpty()) {
            return new Unauthorized(Reason.NOT_FOUND, cpf.masked());
        }
        ClientAccount client = found.get();
        if (!client.isActive()) {
            return new Unauthorized(reasonFor(client), cpf.masked());
        }
        return new Granted(tokens.issue(client, cpf), client, cpf.masked());
    }

    private static Reason reasonFor(ClientAccount client) {
        return switch (client.status()) {
            case BLOCKED -> Reason.BLOCKED;
            default -> Reason.INACTIVE;
        };
    }
}
