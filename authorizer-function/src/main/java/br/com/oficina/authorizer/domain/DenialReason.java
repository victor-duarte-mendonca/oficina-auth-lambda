package br.com.oficina.authorizer.domain;

/**
 * Por que o token foi recusado. Vai só para o log do operador: ao gateway a resposta é sempre um
 * {@code isAuthorized=false} sem detalhe, para o chamador não aprender o que errou.
 */
public enum DenialReason {
    MISSING_HEADER,
    MALFORMED_HEADER,
    MALFORMED_TOKEN,
    UNSUPPORTED_ALGORITHM,
    BAD_SIGNATURE,
    BAD_ISSUER,
    EXPIRED,
    NOT_YET_VALID,
    MISSING_SUBJECT,
    UNKNOWN_ROLE
}
