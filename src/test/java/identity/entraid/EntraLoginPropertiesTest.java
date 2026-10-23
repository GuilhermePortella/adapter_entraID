package identity.entraid;

import identity.entraid.config.EntraLoginProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import static org.assertj.core.api.Assertions.*;

class EntraLoginPropertiesTest {
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"http://example.com/login/oauth2/code/entra", "https://user@example.com/login/oauth2/code/entra",
            "https://example.com/wrong", "https://example.com/login/oauth2/code/entra?query=1",
            "https://example.com/login/oauth2/code/entra#fragment", "not a uri",
            "/login/oauth2/code/entra", "//example.com/login/oauth2/code/entra",
            "http://localhost.evil.test/login/oauth2/code/entra",
            "https://example.com/login/oauth2/code/entra/", "ftp://localhost/login/oauth2/code/entra"})
    void rejectsUnsafeOrIncompatibleRedirect(String redirect) {
        assertThatThrownBy(() -> new EntraLoginProperties(CLIENT, "local-test-secret", redirect))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsHttpsAndLocalCallbackWithoutLeakingSecretInToString() {
        var config = new EntraLoginProperties(CLIENT, "local-test-secret", "https://bff.example.com/login/oauth2/code/entra");
        assertThat(config.toString()).doesNotContain("local-test-secret");
        assertThatCode(() -> new EntraLoginProperties(CLIENT, "local-test-secret", "http://localhost:8080/login/oauth2/code/entra"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsMissingCredentials() {
        assertThatThrownBy(() -> new EntraLoginProperties(CLIENT, "", "http://localhost:8080/login/oauth2/code/entra"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EntraLoginProperties("invalid", "local-test-secret", "http://localhost:8080/login/oauth2/code/entra"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    void rejectsBlankSecret(String secret) {
        assertThatThrownBy(() -> new EntraLoginProperties(CLIENT, secret, "http://localhost:8080/login/oauth2/code/entra"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ENTRA_CLIENT_SECRET");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "invalid", "22222222222222222222222222222222"})
    void rejectsInvalidClientId(String clientId) {
        assertThatThrownBy(() -> new EntraLoginProperties(clientId, "local-test-secret", "http://localhost:8080/login/oauth2/code/entra"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ENTRA_CLIENT_ID");
    }
}
