package br.com.oficina.authorizer.application;

import br.com.oficina.authorizer.domain.AuthorizedCaller;
import br.com.oficina.authorizer.domain.DenialReason;

/** Desfecho da autorização no perímetro. */
public sealed interface AuthorizationDecision {

    record Allowed(AuthorizedCaller caller) implements AuthorizationDecision {
    }

    record Denied(DenialReason reason) implements AuthorizationDecision {
    }
}
