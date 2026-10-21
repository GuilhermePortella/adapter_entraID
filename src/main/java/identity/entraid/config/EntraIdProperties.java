package identity.entraid.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("entra")
public record EntraIdProperties(String tenantId, String audience) {
    private static final String UUID_PATTERN =
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

    public EntraIdProperties {
        requireUuid(tenantId, "ENTRA_TENANT_ID");
        requireUuid(audience, "ENTRA_AUDIENCE");
    }

    private static void requireUuid(String value, String name) {
        if (value == null || !value.matches(UUID_PATTERN)) {
            throw new IllegalArgumentException(name + " deve conter um UUID válido.");
        }
    }

    public String issuer() {
        return "https://login.microsoftonline.com/" + tenantId + "/v2.0";
    }

    public String jwkSetUri() {
        return "https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys";
    }
}
