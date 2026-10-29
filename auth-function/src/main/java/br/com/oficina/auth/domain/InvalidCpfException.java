package br.com.oficina.auth.domain;

/** CPF recusado na validação. A mensagem descreve o defeito, nunca carrega o valor recebido. */
public final class InvalidCpfException extends RuntimeException {

    public InvalidCpfException(String message) {
        super(message);
    }
}
