package br.com.oficina.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class CpfTest {

    /** Os mesmos CPFs válidos dos testes de CpfCnpjValidator da aplicação (rede de segurança da duplicação). */
    @ParameterizedTest
    @ValueSource(strings = {"529.982.247-25", "52998224725", "111.444.777-35", "123.456.789-09", "987.654.321-00",
        "453.178.287-91", " 529 982 247 25 "})
    void parse_shouldAcceptValidCpfWithOrWithoutMask(String raw) {
        assertThat(Cpf.parse(raw).digits()).hasSize(11).containsOnlyDigits();
    }

    @Test
    void parse_shouldNormalizeToElevenDigits() {
        assertThat(Cpf.parse("529.982.247-25").digits()).isEqualTo("52998224725");
    }

    @ParameterizedTest
    @ValueSource(strings = {"529.982.247-24", "52998224726", "11144477736", "12345678900"})
    void parse_shouldRejectWrongCheckDigit(String raw) {
        assertThatThrownBy(() -> Cpf.parse(raw)).isInstanceOf(InvalidCpfException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"00000000000", "11111111111", "22222222222", "33333333333", "44444444444",
        "55555555555", "66666666666", "77777777777", "88888888888", "99999999999"})
    void parse_shouldRejectRepeatedSequences(String raw) {
        // Passam no cálculo dos dígitos verificadores: é o caso de teste que mais escapa.
        assertThatThrownBy(() -> Cpf.parse(raw)).isInstanceOf(InvalidCpfException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"123", "529982247250", "abc", "529.982.247", "529.982.247-2"})
    void parse_shouldRejectWrongLengthOrNonNumeric(String raw) {
        assertThatThrownBy(() -> Cpf.parse(raw)).isInstanceOf(InvalidCpfException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void parse_shouldRejectMissing(String raw) {
        assertThatThrownBy(() -> Cpf.parse(raw)).isInstanceOf(InvalidCpfException.class);
    }

    @Test
    void masked_shouldHideTheMiddleDigits() {
        assertThat(Cpf.parse("529.982.247-25").masked()).isEqualTo("529******25");
    }

    @Test
    void toString_shouldNeverExposeTheFullCpf() {
        assertThat(Cpf.parse("52998224725").toString()).doesNotContain("52998224725").contains("529******25");
    }

    @Test
    void exceptionMessage_shouldNeverCarryTheReceivedValue() {
        assertThatThrownBy(() -> Cpf.parse("529.982.247-24"))
            .hasMessageNotContaining("529").hasMessageNotContaining("24");
    }
}
