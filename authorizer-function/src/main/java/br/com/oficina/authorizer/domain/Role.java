package br.com.oficina.authorizer.domain;

import java.util.Collection;
import java.util.Optional;

/**
 * Papéis conhecidos, em ordem de precedência (do mais privilegiado ao menos). O authorizer só confere
 * que o token carrega <b>algum</b> papel conhecido; quem decide o que cada papel pode fazer é a
 * aplicação ({@code @RolesAllowed}) — nenhuma das duas camadas confia na outra (spec 03 §4).
 */
public enum Role {
    ADMIN,
    MECHANIC,
    CLIENT;

    /** O papel de maior precedência entre os grupos do token, ou vazio se nenhum for conhecido. */
    public static Optional<Role> highestOf(Collection<String> groups) {
        for (Role role : values()) {
            if (groups.contains(role.name())) {
                return Optional.of(role);
            }
        }
        return Optional.empty();
    }
}
