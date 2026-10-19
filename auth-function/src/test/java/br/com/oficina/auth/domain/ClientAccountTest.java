package br.com.oficina.auth.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ClientAccountTest {

    @ParameterizedTest
    @CsvSource({
        "Maria Souza, Maria S.",
        "João Carlos de Oliveira, João O.",
        "'  Ana   Lima  ', Ana L.",
        "Cher, Cher"
    })
    void displayName_shouldShowFirstNameAndLastInitialOnly(String fullName, String expected) {
        assertThat(new ClientAccount(1, fullName, ClientStatus.ACTIVE).displayName()).isEqualTo(expected);
    }

    @Test
    void isActive_shouldBeTrueOnlyForActive() {
        assertThat(new ClientAccount(1, "A", ClientStatus.ACTIVE).isActive()).isTrue();
        assertThat(new ClientAccount(1, "A", ClientStatus.INACTIVE).isActive()).isFalse();
        assertThat(new ClientAccount(1, "A", ClientStatus.BLOCKED).isActive()).isFalse();
        assertThat(new ClientAccount(1, "A", ClientStatus.UNKNOWN).isActive()).isFalse();
    }

    @ParameterizedTest
    @CsvSource({"ACTIVE, ACTIVE", "active, ACTIVE", "' BLOCKED ', BLOCKED", "INACTIVE, INACTIVE", "SUSPENSO, UNKNOWN"})
    void clientStatus_fromDatabase_shouldMapKnownValuesAndFallBackToUnknown(String value, ClientStatus expected) {
        assertThat(ClientStatus.fromDatabase(value)).isEqualTo(expected);
    }

    @Test
    void clientStatus_fromDatabase_shouldTreatNullAsUnknown() {
        assertThat(ClientStatus.fromDatabase(null)).isEqualTo(ClientStatus.UNKNOWN);
    }
}
