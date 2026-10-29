package br.com.oficina.auth.infrastructure;

import br.com.oficina.auth.application.AuthenticateByCpf;
import br.com.oficina.auth.domain.ClientAccount;
import br.com.oficina.auth.domain.ClientStatus;
import br.com.oficina.auth.domain.Cpf;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.time.Clock;
import javax.sql.DataSource;

/**
 * Monta as dependências uma vez por ambiente de execução, na inicialização — que é a fase capturada pelo
 * snapshot do SnapStart. O que for caro e seguro de guardar (chave RSA lida, classes carregadas) entra
 * no snapshot; o que tem socket (pool JDBC) <b>não</b>: é criado sob demanda no primeiro uso depois da
 * restauração.
 */
final class Composition {

    /** Holder idiom: a inicialização é preguiçosa e thread-safe, sem sincronização no caminho quente. */
    private static final class Holder {
        static final Composition INSTANCE = new Composition();
    }

    private final AppConfig config;
    private final JwtTokenIssuer tokenIssuer;
    private final StructuredLogger logger;
    private final AuthenticateByCpf useCase;
    private HikariDataSource pool;

    private Composition() {
        this.config = AppConfig.fromEnvironment();
        this.logger = new StructuredLogger(System.out);
        this.tokenIssuer = new JwtTokenIssuer(
            PemKeys.privateKey(config.jwtPrivateKeyPem()), config.jwtIssuer(), config.jwtTtlSeconds(), Clock.systemUTC());
        this.useCase = new AuthenticateByCpf(new PostgresClientLookup(this::dataSource), tokenIssuer);
        SnapStartHooks.register(this::prime, this::closePool);
    }

    static AuthenticateByCpf useCase() {
        return Holder.INSTANCE.useCase;
    }

    static StructuredLogger logger() {
        return Holder.INSTANCE.logger;
    }

    /** Pool minúsculo (spec 02 §4): o db.t4g.micro tem teto de ~112 conexões e o Lambda tem concorrência 10. */
    private synchronized DataSource dataSource() {
        if (pool == null) {
            HikariConfig hikari = new HikariConfig();
            hikari.setJdbcUrl(config.jdbcUrl());
            hikari.setUsername(config.dbUser());
            hikari.setPassword(config.dbPassword());
            hikari.setMaximumPoolSize(2);
            hikari.setMinimumIdle(0);
            hikari.setConnectionTimeout(3_000);
            // Não falha ao subir o pool: a função só abre conexão quando atende uma requisição.
            hikari.setInitializationFailTimeout(-1);
            // Defesa em profundidade além do papel somente-leitura do banco.
            hikari.setReadOnly(true);
            hikari.setPoolName("oficina-auth");
            pool = new HikariDataSource(hikari);
        }
        return pool;
    }

    private synchronized void closePool() {
        if (pool != null) {
            pool.close();
            pool = null;
        }
    }

    /**
     * Aquece, antes do checkpoint, o caminho de CPF e de assinatura (carrega e inicializa as classes de
     * criptografia). Não toca o banco e descarta o token: nada sensível sobra no snapshot.
     */
    private void prime() {
        Cpf cpf = Cpf.parse("529.982.247-25");
        tokenIssuer.issue(new ClientAccount(0, "Aquecimento do Snapstart", ClientStatus.ACTIVE), cpf);
    }
}
