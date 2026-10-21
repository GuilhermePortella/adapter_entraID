package identity.entraid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import identity.entraid.config.EntraIdProperties;
import java.time.Instant;
import java.util.Date;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "entra.tenant-id=00000000-0000-0000-0000-000000000000",
        "entra.audience=11111111-1111-1111-1111-111111111111"
})
@AutoConfigureMockMvc
@Import(ApiSecurityTest.TestKeys.class)
class ApiSecurityTest {
    private static final RSAKey KEY = newKey();
    @Autowired MockMvc mvc;
    @Autowired EntraIdProperties properties;

    private static RSAKey newKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class TestKeys {
        // Replace only the key source. Keep real signature verification and production validators.
        @Bean
        @Primary
        JwtDecoder localDecoder(OAuth2TokenValidator<Jwt> validator) throws JOSEException {
            var decoder = NimbusJwtDecoder.withPublicKey(KEY.toRSAPublicKey()).build();
            decoder.setJwtValidator(validator);
            return decoder;
        }
    }

    private String token(Consumer<JWTClaimsSet.Builder> customize, RSAKey key) throws JOSEException {
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer()).audience(properties.audience())
                .subject("test-subject").issueTime(Date.from(now))
                .notBeforeTime(Date.from(now.minusSeconds(5)))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("tid", properties.tenantId()).claim("ver", "2.0")
                .claim("scp", "access_as_user");
        customize.accept(claims);
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void protectedEndpointRequiresBearerToken() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void validSignedTokenGrantsAccessWithoutSessionOrTokenDisclosure() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token(c -> {}, KEY)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("test-subject"))
                .andExpect(jsonPath("$.tenantId").value(properties.tenantId()))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(cookie().doesNotExist("JSESSIONID"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"issuer", "audience", "tenant", "version", "expired", "future", "no-exp", "no-sub"})
    void invalidClaimsAreRejected(String scenario) throws Exception {
        String bearer = token(c -> {
            switch (scenario) {
                case "issuer" -> c.issuer("https://attacker.invalid/v2.0");
                case "audience" -> c.audience("00000003-0000-0000-c000-000000000000"); // Microsoft Graph
                case "tenant" -> c.claim("tid", "22222222-2222-2222-2222-222222222222");
                case "version" -> c.claim("ver", "1.0");
                case "expired" -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)));
                case "future" -> c.notBeforeTime(Date.from(Instant.now().plusSeconds(120)));
                case "no-exp" -> c.expirationTime(null);
                case "no-sub" -> c.subject(null);
                default -> throw new IllegalArgumentException(scenario);
            }
        }, KEY);
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + bearer))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void untrustedSignatureIsRejected() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token(c -> {}, newKey())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void malformedTokenIsRejected() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer invalid"))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "other_scope", "access_as_user_extra"})
    void missingOrIncorrectScopeIsForbidden(String scope) throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token(c -> c.claim("scp", scope), KEY)))
                .andExpect(status().isForbidden());
    }

    @Test
    void applicationRoleDoesNotReplaceDelegatedScope() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token(c ->
                c.claim("scp", null).claim("roles", java.util.List.of("access_as_user")), KEY)))
                .andExpect(status().isForbidden());
    }

    @Test
    void unlistedRoutesAndMethodsAreDenied() throws Exception {
        String bearer = "Bearer " + token(c -> {}, KEY);
        mvc.perform(get("/api/other").header("Authorization", bearer)).andExpect(status().isForbidden());
        mvc.perform(post("/api/me").header("Authorization", bearer)).andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "common", "organizations", "../tenant", "not-a-uuid"})
    void invalidConfigurationIsRejected(String value) {
        assertThatThrownBy(() -> new EntraIdProperties(value, properties.audience()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EntraIdProperties(properties.tenantId(), value))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
