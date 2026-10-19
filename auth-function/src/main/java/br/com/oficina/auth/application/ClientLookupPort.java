package br.com.oficina.auth.application;

import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.Cpf;
import java.util.Optional;

/** Porta de saída: localiza o cliente pelo CPF, em qualquer situação (o caso de uso decide). */
public interface ClientLookupPort {

    /**
     * @throws RuntimeException em falha de infraestrutura (banco indisponível); nunca devolve vazio
     *                          para esconder um erro
     */
    Optional<ClientAccount> findByCpf(Cpf cpf);
}
