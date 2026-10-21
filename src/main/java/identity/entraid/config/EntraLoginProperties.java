package identity.entraid.config;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("entra.login")
public final class EntraLoginProperties {
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    public EntraLoginProperties(String clientId, String clientSecret, String redirectUri) {
        if (clientId == null || !clientId.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            throw new IllegalArgumentException("ENTRA_CLIENT_ID deve conter um UUID válido.");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("ENTRA_CLIENT_SECRET é obrigatório para login OIDC.");
        }
        URI uri;
        try {
            uri = URI.create(redirectUri);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("ENTRA_REDIRECT_URI inválida.");
        }
        boolean https = "https".equals(uri.getScheme());
        boolean localHttp = "http".equals(uri.getScheme()) && "localhost".equals(uri.getHost());
        if ((!https && !localHttp) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || !"/login/oauth2/code/entra".equals(uri.getPath())) {
            throw new IllegalArgumentException("ENTRA_REDIRECT_URI deve usar HTTPS (ou HTTP localhost) e /login/oauth2/code/entra.");
        }
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    public String clientId() { return clientId; }
    public String clientSecret() { return clientSecret; }
    public String redirectUri() { return redirectUri; }
    // Deliberately no generated toString: this object contains a secret.
}
