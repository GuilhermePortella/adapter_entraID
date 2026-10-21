package identity.entraid.config;

import java.time.Duration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableConfigurationProperties(EntraIdProperties.class)
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Only Authorization: Bearer is accepted; no cookie/session authentication.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/health").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/me").hasAuthority("SCOPE_access_as_user")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    JwtDecoder jwtDecoder(EntraIdProperties properties, OAuth2TokenValidator<Jwt> tokenValidator) {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(5));
        factory.setReadTimeout(Duration.ofSeconds(5));
        var decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .restOperations(new RestTemplate(factory))
                .build();
        decoder.setJwtValidator(tokenValidator);
        return decoder;
    }

    @Bean
    OAuth2TokenValidator<Jwt> tokenValidator(EntraIdProperties properties) {
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            boolean valid = jwt.getAudience().contains(properties.audience())
                    && properties.tenantId().equals(jwt.getClaimAsString("tid"))
                    && "2.0".equals(jwt.getClaimAsString("ver"))
                    && jwt.getExpiresAt() != null
                    && jwt.getSubject() != null && !jwt.getSubject().isBlank();
            return valid ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(
                            new OAuth2Error("invalid_token", "Token incompatível com esta API.", null));
        };
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()), claims);
    }
}
