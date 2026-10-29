package br.com.oficina.auth.domain;

/**
 * Value Object de CPF: imutável e válido por construção. Reimplementa o algoritmo de
 * {@code CpfCnpjValidator} da aplicação de propósito — publicar um artefato compartilhado para ~40 linhas
 * estáveis há décadas acoplaria dois repositórios que a fase pede separados (spec 02 §5). O teste de
 * equivalência com os casos da aplicação é a rede de segurança.
 */
public final class Cpf {

    private static final int LENGTH = 11;

    private final String digits;

    private Cpf(String digits) {
        this.digits = digits;
    }

    /**
     * Aceita CPF com ou sem máscara; normaliza para 11 dígitos antes de qualquer outra coisa.
     *
     * @throws InvalidCpfException se ausente, de tamanho errado, sequência repetida ou com dígito
     *                             verificador incorreto
     */
    public static Cpf parse(String raw) {
        if (raw == null) {
            throw new InvalidCpfException("CPF ausente");
        }
        String digits = raw.replaceAll("\\D", "");
        if (digits.length() != LENGTH) {
            throw new InvalidCpfException("CPF deve ter 11 dígitos");
        }
        if (isRepeatedSequence(digits)) {
            // Passam no cálculo dos dígitos verificadores; é o caso que mais escapa.
            throw new InvalidCpfException("CPF com sequência repetida");
        }
        if (!hasValidCheckDigits(digits)) {
            throw new InvalidCpfException("CPF com dígito verificador inválido");
        }
        return new Cpf(digits);
    }

    /** Os 11 dígitos, sem máscara — é como o CPF está gravado em {@code clients.cpf_cnpj}. */
    public String digits() {
        return digits;
    }

    /**
     * Forma segura para claim e log: {@code 529******25}. O token trafega em logs de gateway e em
     * ferramentas de observabilidade; o CPF completo ali seria dado pessoal exposto por padrão.
     */
    public String masked() {
        return digits.substring(0, 3) + "******" + digits.substring(9);
    }

    /** Nunca devolve o CPF: este objeto pode acabar numa mensagem de log. */
    @Override
    public String toString() {
        return "Cpf[" + masked() + "]";
    }

    private static boolean isRepeatedSequence(String digits) {
        return digits.chars().distinct().count() == 1;
    }

    private static boolean hasValidCheckDigits(String digits) {
        int first = checkDigit(digits, 9);
        int second = checkDigit(digits, 10);
        return first == Character.digit(digits.charAt(9), 10)
            && second == Character.digit(digits.charAt(10), 10);
    }

    /** Módulo 11 sobre os primeiros {@code length} dígitos, com pesos de {@code length + 1} até 2. */
    private static int checkDigit(String digits, int length) {
        int sum = 0;
        for (int i = 0; i < length; i++) {
            sum += Character.digit(digits.charAt(i), 10) * (length + 1 - i);
        }
        int remainder = (sum * 10) % 11;
        return remainder == 10 ? 0 : remainder;
    }
}
