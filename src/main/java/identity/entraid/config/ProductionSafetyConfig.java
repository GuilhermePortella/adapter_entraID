package identity.entraid.config;

import java.net.URI;
import java.util.Arrays;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

/** Refuse accidental local settings before the production web server starts. */
@Configuration(proxyBeanMethods = false)
@Profile("prod")
@EnableConfigurationProperties(ServerProperties.class)
public class ProductionSafetyConfig {
    public ProductionSafetyConfig(Environment environment, ServerProperties server) {
        require(!Arrays.asList(environment.getActiveProfiles()).contains("local"),
                "Os perfis prod e local não podem ser combinados.");
        require(server.getSsl() != null && server.getSsl().isEnabled(),
                "Produção exige TLS no Java (server.ssl.enabled=true). Configure o certificado externo.");
        require(server.getForwardHeadersStrategy() == ServerProperties.ForwardHeadersStrategy.NONE,
                "Produção não aceita forwarded headers sem configuração de proxy confiável.");
        var cookie = server.getServlet().getSession().getCookie();
        require(Boolean.TRUE.equals(cookie.getSecure()), "Produção exige cookie Secure.");
        require(Boolean.TRUE.equals(cookie.getHttpOnly()), "Produção exige cookie HttpOnly.");
        require(cookie.getSameSite() != null, "Produção exige SameSite no cookie de sessão.");
        if (environment.getProperty("entra.login.enabled", Boolean.class, false)) {
            URI callback;
            try {
                callback = URI.create(environment.getProperty("entra.login.redirect-uri", ""));
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Configure um callback HTTPS válido para produção.");
            }
            String host = callback.getHost();
            require("https".equals(callback.getScheme()) && host != null
                            && !host.equalsIgnoreCase("localhost") && !host.endsWith(".localhost")
                            && !host.equals("127.0.0.1") && !host.equals("[::1]"),
                    "Produção exige callback HTTPS com hostname de implantação, sem localhost.");
        }
    }

    private static void require(boolean valid, String message) {
        if (!valid) throw new IllegalStateException(message);
    }
}
