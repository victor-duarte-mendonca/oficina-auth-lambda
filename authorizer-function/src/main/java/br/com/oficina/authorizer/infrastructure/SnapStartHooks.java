package br.com.oficina.authorizer.infrastructure;

import org.crac.Context;
import org.crac.Core;
import org.crac.Resource;

/**
 * Hook de checkpoint do SnapStart: aquece o caminho de criptografia antes do snapshot. Não há nada a
 * refazer depois da restauração — sem conexões, o estado capturado é só a chave pública e as classes.
 */
final class SnapStartHooks implements Resource {

    /**
     * O contexto global do CRaC guarda os recursos por referência <b>fraca</b>; sem uma referência forte
     * aqui o coletor de lixo descartaria o hook e ele nunca rodaria.
     */
    private static SnapStartHooks registered;

    private final Runnable prime;

    private SnapStartHooks(Runnable prime) {
        this.prime = prime;
    }

    static synchronized void register(Runnable prime) {
        registered = new SnapStartHooks(prime);
        Core.getGlobalContext().register(registered);
    }

    @Override
    public void beforeCheckpoint(Context<? extends Resource> context) {
        try {
            prime.run();
        } catch (RuntimeException ignored) {
            // O aquecimento é só otimização.
        }
    }

    @Override
    public void afterRestore(Context<? extends Resource> context) {
        // Nada a refazer.
    }
}
