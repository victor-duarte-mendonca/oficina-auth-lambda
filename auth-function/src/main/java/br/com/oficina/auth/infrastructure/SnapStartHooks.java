package br.com.oficina.auth.infrastructure;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

/**
 * Hooks de checkpoint/restore do SnapStart. Antes do snapshot: aquece o caminho de criptografia e fecha
 * qualquer pool JDBC (um socket aberto morreria na restauração). Depois da restauração não há o que
 * refazer: o pool é recriado sob demanda no primeiro atendimento.
 */
final class SnapStartHooks implements Resource {

    /**
     * O contexto global do CRaC guarda os recursos por referência <b>fraca</b>; sem uma referência forte
     * aqui o coletor de lixo descartaria o hook e ele nunca rodaria.
     */
    private static SnapStartHooks registered;

    private final Runnable prime;
    private final Runnable closePool;

    private SnapStartHooks(Runnable prime, Runnable closePool) {
        this.prime = prime;
        this.closePool = closePool;
    }

    static synchronized void register(Runnable prime, Runnable closePool) {
        registered = new SnapStartHooks(prime, closePool);
        Core.getGlobalContext().register(registered);
    }

    @Override
    public void beforeCheckpoint(Context<? extends Resource> context) {
        try {
            prime.run();
        } catch (RuntimeException ignored) {
            // O aquecimento é só otimização: falhar aqui não pode impedir a publicação da versão.
        }
        closePool.run();
    }

    @Override
    public void afterRestore(Context<? extends Resource> context) {
        // Nada: o pool é criado sob demanda.
    }
}
