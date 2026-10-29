package br.com.oficina.auth.infrastructure;

import br.com.oficina.auth.application.ClientLookupPort;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.ClientStatus;
import br.com.oficina.auth.domain.Cpf;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.function.Supplier;
import javax.sql.DataSource;

/**
 * Consulta o cliente pelo CPF com o papel somente-leitura {@code oficina_auth_ro}, que só enxerga
 * {@code id, name, cpf_cnpj, client_type, status} (migration V6 da aplicação). O {@code DataSource} é
 * obtido sob demanda: com SnapStart, uma conexão aberta na inicialização morreria na restauração.
 */
public final class PostgresClientLookup implements ClientLookupPort {

    /** Sem filtro de status: o caso de uso precisa do status para decidir (e logar o motivo). */
    static final String QUERY = "SELECT id, name, status FROM clients WHERE cpf_cnpj = ?";

    private final Supplier<DataSource> dataSource;

    public PostgresClientLookup(Supplier<DataSource> dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Optional<ClientAccount> findByCpf(Cpf cpf) {
        try (Connection connection = dataSource.get().getConnection();
             PreparedStatement statement = connection.prepareStatement(QUERY)) {
            statement.setString(1, cpf.digits());
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new ClientAccount(
                    rs.getLong("id"), rs.getString("name"), ClientStatus.fromDatabase(rs.getString("status"))));
            }
        } catch (SQLException e) {
            throw new ClientLookupException(e.getSQLState(), e);
        }
    }

    /** Falha de banco. Carrega só o SQLState: a mensagem do driver pode conter host/banco. */
    public static final class ClientLookupException extends RuntimeException {

        private final String sqlState;

        ClientLookupException(String sqlState, SQLException cause) {
            super("Falha ao consultar o cliente (SQLState=" + sqlState + ")", cause);
            this.sqlState = sqlState;
        }

        public String sqlState() {
            return sqlState;
        }
    }
}
