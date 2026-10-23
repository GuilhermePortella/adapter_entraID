package identity.entraid;

import identity.entraid.config.EntraIdProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class EntraIdPropertiesTest {
    private static final String TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static final String AUDIENCE = "11111111-2222-3333-4444-555555555555";

    @Test
    void buildsTenantSpecificMicrosoftEndpoints() {
        var properties = new EntraIdProperties(TENANT, AUDIENCE);

        assertThat(properties.issuer()).isEqualTo("https://login.microsoftonline.com/" + TENANT + "/v2.0");
        assertThat(properties.jwkSetUri()).isEqualTo("https://login.microsoftonline.com/" + TENANT + "/discovery/v2.0/keys");
        assertThat(properties.audience()).isEqualTo(AUDIENCE);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "invalid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/other", " aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
    void rejectsInvalidTenant(String tenant) {
        assertThatThrownBy(() -> new EntraIdProperties(tenant, AUDIENCE))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ENTRA_TENANT_ID");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "invalid", "api://11111111-2222-3333-4444-555555555555"})
    void rejectsInvalidAudience(String audience) {
        assertThatThrownBy(() -> new EntraIdProperties(TENANT, audience))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ENTRA_AUDIENCE");
    }
}
