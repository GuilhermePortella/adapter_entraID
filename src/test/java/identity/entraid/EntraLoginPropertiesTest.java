package identity.entraid;

import identity.entraid.config.EntraLoginProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class EntraLoginPropertiesTest {
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/login/oauth2/code/entra", "https://user@example.com/login/oauth2/code/entra",
            "https://example.com/wrong", "https://example.com/login/oauth2/code/entra?query=1",
            "https://example.com/login/oauth2/code/entra#fragment", "not a uri"})
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
}
