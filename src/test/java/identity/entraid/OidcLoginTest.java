package identity.entraid;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.Arrays;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "entra.tenant-id=00000000-0000-0000-0000-000000000000",
        "entra.audience=11111111-1111-1111-1111-111111111111",
        "entra.login.enabled=true",
        "entra.login.client-id=22222222-2222-2222-2222-222222222222",
        "entra.login.client-secret=local-test-only",
        "entra.login.redirect-uri=http://localhost:8080/login/oauth2/code/entra"
})
@AutoConfigureMockMvc
@Import(OidcLoginTest.LocalProvider.class)
class OidcLoginTest {
    private static final String ISSUER = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0";
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final RSAKey KEY;
    private static final RSAKey OTHER_KEY;
    private static final HttpServer SERVER;
    private static volatile String scenario = "valid";
    private static volatile String nonce;
    private static volatile Map<String, String> tokenForm = Map.of();
    private static final AtomicInteger TOKEN_CALLS = new AtomicInteger();

    static {
        try {
            KEY = new RSAKeyGenerator(2048).keyID("local-key").generate();
            OTHER_KEY = new RSAKeyGenerator(2048).keyID("local-key").generate();
            SERVER = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            SERVER.createContext("/jwks", exchange -> {
                byte[] bytes = new JWKSet(KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (var out = exchange.getResponseBody()) { out.write(bytes); }
            });
            SERVER.createContext("/token", exchange -> {
                TOKEN_CALLS.incrementAndGet();
                tokenForm = parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                try {
                    boolean failure = List.of("invalid_client", "provider_unavailable").contains(scenario);
                    Map<String, Object> body = failure
                            ? Map.of("error", "invalid_client", "error_description", "SENSITIVE_PROVIDER_DETAIL")
                            : Map.of("access_token", "test-access-token", "token_type", "Bearer", "expires_in", 300,
                                    "scope", "openid profile email", "id_token", idToken());
                    byte[] bytes = JSON.writeValueAsBytes(body);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(failure ? ("invalid_client".equals(scenario) ? 401 : 503) : 200,
                            bytes.length);
                    try (var out = exchange.getResponseBody()) { out.write(bytes); }
                } catch (Exception e) {
                    exchange.close();
                    throw new IllegalStateException(e);
                }
            });
            SERVER.start();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class LocalProvider {
        @Bean
        @Primary
        ClientRegistrationRepository localRegistrations(
                @Qualifier("clientRegistrations") ClientRegistrationRepository actual) {
            String base = "http://127.0.0.1:" + SERVER.getAddress().getPort();
            // Only network endpoints change. The real token client, OIDC decoder and filters run unchanged.
            var registration = ClientRegistration.withClientRegistration(actual.findByRegistrationId("entra"))
                    .tokenUri(base + "/token").jwkSetUri(base + "/jwks").build();
            return new InMemoryClientRegistrationRepository(registration);
        }
    }

    @Autowired MockMvc mvc;
    @LocalServerPort int port;

    @BeforeEach
    void reset() {
        scenario = "valid";
        tokenForm = Map.of();
        TOKEN_CALLS.set(0);
    }

    @AfterAll
    static void stop() { SERVER.stop(0); }

    private static Map<String, String> parseForm(String body) {
        return Arrays.stream(body.split("&")).map(part -> part.split("=", 2))
                .collect(Collectors.toMap(pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                        pair -> URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8)));
    }

    private static String idToken() throws Exception {
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder().issuer(ISSUER).audience(CLIENT).subject("test-user")
                .issueTime(Date.from(now.minusSeconds(5))).expirationTime(Date.from(now.plusSeconds(300)))
                .claim("nonce", nonce).claim("tid", "00000000-0000-0000-0000-000000000000")
                .claim("name", "Usuario Teste").claim("email", "usuario@example.com")
                .claim("preferred_username", "not-an-email");
        switch (scenario) {
            case "issuer" -> claims.issuer("https://untrusted.invalid");
            case "audience" -> claims.audience("wrong-client");
            case "expired" -> claims.expirationTime(Date.from(now.minusSeconds(120)));
            case "nonce" -> claims.claim("nonce", "incorrect-nonce");
            case "missing-nonce" -> claims.claim("nonce", null);
            case "missing-email" -> claims.claim("email", null);
            case "optional-claims" -> claims.claim("email", null).claim("name", null).claim("tid", null);
            default -> { }
        }
        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY.getKeyID()).build(), claims.build());
        signed.sign(new RSASSASigner("signature".equals(scenario) ? OTHER_KEY : KEY));
        return signed.serialize();
    }

    private record LoginAttempt(MockHttpSession session, String state) { }

    private LoginAttempt begin() throws Exception {
        var result = mvc.perform(get("/oauth2/authorization/entra"))
                .andExpect(status().is3xxRedirection()).andReturn();
        URI redirect = URI.create(result.getResponse().getRedirectedUrl());
        assertThat(redirect.getHost()).isEqualTo("login.microsoftonline.com");
        var query = parseForm(redirect.getRawQuery());
        nonce = query.get("nonce");
        assertThat(nonce).isNotBlank();
        assertThat(query.get("state")).isNotBlank();
        assertThat(query.get("code_challenge_method")).isEqualTo("S256");
        assertThat(query.get("code_challenge")).isNotBlank();
        assertThat(query.get("response_type")).isEqualTo("code");
        assertThat(query.get("scope").split(" ")).containsExactlyInAnyOrder("openid", "profile", "email");
        return new LoginAttempt((MockHttpSession) result.getRequest().getSession(false), query.get("state"));
    }

    private MockHttpSession login() throws Exception {
        LoginAttempt attempt = begin();
        String previousId = attempt.session().getId();
        var result = mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("code", "test-code").param("state", attempt.state()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/demo/index.html")).andReturn();
        var session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session.getId()).isNotEqualTo(previousId);
        assertThat(tokenForm).containsEntry("grant_type", "authorization_code")
                .containsEntry("client_id", CLIENT).containsEntry("client_secret", "local-test-only")
                .containsEntry("redirect_uri", "http://localhost:8080/login/oauth2/code/entra")
                .containsKey("code_verifier");
        return session;
    }

    @Test
    void anonymousUserIsRedirectedToLoginWhileBearerApiStillReturns401() throws Exception {
        mvc.perform(get("/auth/me")).andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/oauth2/authorization/entra"));
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/health")).andExpect(status().isOk());
    }

    @Test
    void loginEndpointStartsOidc() throws Exception {
        mvc.perform(get("/demo/index.html")).andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Entrar com Microsoft")));
        mvc.perform(get("/login")).andExpect(status().isFound())
                .andExpect(redirectedUrl("/oauth2/authorization/entra"));
    }

    @Test
    void fullCodeFlowReturnsOnlyBasicIdentityAndPreservesBearerIsolation() throws Exception {
        var session = login();
        var result = mvc.perform(get("/auth/me").session(session)).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andReturn();
        assertThat(JSON.readTree(result.getResponse().getContentAsString())).isEqualTo(JSON.readTree("""
                {"authenticated":true,"provider":"Microsoft Entra ID","user":{
                  "name":"Usuario Teste","email":"usuario@example.com","subject":"test-user",
                  "tenantId":"00000000-0000-0000-0000-000000000000"}}
                """));
        mvc.perform(get("/api/me").session(session)).andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/test").session(session)).andExpect(status().isForbidden());
        mvc.perform(get("/private").session(session)).andExpect(status().isForbidden());
        mvc.perform(get("/not-allowed").session(session)).andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing-email", "optional-claims"})
    void optionalClaimsAreNullWithoutInventingAnEmail(String variant) throws Exception {
        scenario = variant;
        var response = mvc.perform(get("/auth/me").session(login()))
                .andExpect(status().isOk()).andReturn();
        var body = JSON.readTree(response.getResponse().getContentAsString());
        assertThat(body.get("authenticated").asBoolean()).isTrue();
        assertThat(body.get("user").get("subject").asText()).isEqualTo("test-user");
        assertThat(body.get("user").get("email").isNull()).isTrue();
        if ("optional-claims".equals(variant)) {
            assertThat(body.get("user").get("name").isNull()).isTrue();
            assertThat(body.get("user").get("tenantId").isNull()).isTrue();
        }
    }

    @Test
    void cancelledLoginDoesNotAuthenticateOrExchangeCode() throws Exception {
        var attempt = begin();
        mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("error", "access_denied").param("state", attempt.state()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().json("{\"error\":\"authentication_failed\"}"));
        assertThat(TOKEN_CALLS.get()).isZero();
        mvc.perform(get("/auth/me").session(attempt.session())).andExpect(status().is3xxRedirection());
    }

    @ParameterizedTest
    @ValueSource(strings = {"signature", "issuer", "audience", "expired", "nonce", "missing-nonce",
            "invalid_client", "provider_unavailable"})
    void invalidIdentityOrProviderFailureCannotCreateAuthenticatedSession(String variant) throws Exception {
        scenario = variant;
        var attempt = begin();
        mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("code", "test-code").param("state", attempt.state()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().json("{\"error\":\"authentication_failed\"}"));
        mvc.perform(get("/auth/me").session(attempt.session())).andExpect(status().is3xxRedirection());
    }

    @Test
    void invalidStateAndUnsolicitedCallbackAreRejectedBeforeTokenExchange() throws Exception {
        var attempt = begin();
        mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("code", "test-code").param("state", "invalid"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/login/oauth2/code/entra").param("code", "test-code").param("state", "unknown"))
                .andExpect(status().isUnauthorized());
        assertThat(TOKEN_CALLS.get()).isZero();
    }

    @Test
    void incompleteCallbackIsRejected() throws Exception {
        mvc.perform(get("/login/oauth2/code/entra")).andExpect(status().isUnauthorized());
        assertThat(TOKEN_CALLS.get()).isZero();
    }

    @Test
    void callbackCannotBeReplayed() throws Exception {
        var attempt = begin();
        mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("code", "test-code").param("state", attempt.state()))
                .andExpect(status().is3xxRedirection());
        mvc.perform(get("/login/oauth2/code/entra").session(attempt.session())
                        .param("code", "test-code").param("state", attempt.state()))
                .andExpect(status().isUnauthorized());
        assertThat(TOKEN_CALLS.get()).isEqualTo(1);
    }

    @Test
    void realServletContainerIssuesProtectedSessionCookie() throws Exception {
        try (var client = java.net.http.HttpClient.newHttpClient()) {
            var request = java.net.http.HttpRequest.newBuilder(
                    URI.create("http://localhost:" + port + "/oauth2/authorization/entra")).GET().build();
            var response = client.send(request, java.net.http.HttpResponse.BodyHandlers.discarding());
            assertThat(response.statusCode()).isEqualTo(302);
            assertThat(response.headers().firstValue("set-cookie").orElseThrow())
                    .contains("JSESSIONID=", "HttpOnly", "Secure", "SameSite=Lax");
            assertThat(response.headers().firstValue("location").orElseThrow()).doesNotContain(";jsessionid");
        }
    }

    @Test
    void logoutRequiresRealCsrfTokenAndInvalidatesSession() throws Exception {
        var session = login();
        mvc.perform(post("/logout").session(session)).andExpect(status().isForbidden());
        assertThat(session.isInvalid()).isFalse();
        var response = mvc.perform(get("/csrf").session(session)).andExpect(status().isOk()).andReturn();
        var csrf = JSON.readTree(response.getResponse().getContentAsString());
        mvc.perform(post("/logout").session(session).header(csrf.get("headerName").asText(), csrf.get("token").asText()))
                .andExpect(status().isNoContent()).andExpect(cookie().maxAge("JSESSIONID", 0));
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/auth/me").cookie(new jakarta.servlet.http.Cookie("JSESSIONID", "expired-session")))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void idTokenExpirationEndsAnOtherwiseActiveSession() throws Exception {
        var session = new MockHttpSession();
        var token = new OidcIdToken("test-token", Instant.now().minusSeconds(600), Instant.now().minusSeconds(1),
                Map.of("sub", "test-user"));
        var authorities = List.of(new SimpleGrantedAuthority("OIDC_USER"));
        var user = new DefaultOidcUser(authorities, token);
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new OAuth2AuthenticationToken(user, authorities, "entra"));
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        mvc.perform(get("/auth/me").session(session)).andExpect(status().is3xxRedirection());
        assertThat(session.isInvalid()).isTrue();
    }
}
