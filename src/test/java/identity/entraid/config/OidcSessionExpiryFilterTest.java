package identity.entraid.config;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import static org.assertj.core.api.Assertions.assertThat;

class OidcSessionExpiryFilterTest {
    private final OidcSessionExpiryFilter filter = new OidcSessionExpiryFilter();
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/me");
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final MockFilterChain chain = new MockFilterChain();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void anonymousRequestContinuesForDownstreamAuthorization() throws Exception {
        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(request.getSession(false)).isNull();
    }

    @Test
    void nonOidcAuthenticationIsPreserved() throws Exception {
        var authentication = new UsernamePasswordAuthenticationToken("user", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
    }

    @Test
    void validIdTokenPreservesSessionAndAuthentication() throws Exception {
        var authentication = authenticate(Instant.now().plusSeconds(3600));
        var session = new MockHttpSession();
        request.setSession(session);

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(session.isInvalid()).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
        assertThat(response.getRedirectedUrl()).isNull();
    }

    @Test
    void expiredIdTokenInvalidatesSessionAndStopsRequest() throws Exception {
        authenticate(Instant.now().minusSeconds(60));
        var session = new MockHttpSession();
        request.setSession(session);

        filter.doFilter(request, response, chain);

        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/oauth2/authorization/entra");
    }

    @Test
    void expiredIdentityWithoutSessionStillRedirectsToLogin() throws Exception {
        authenticate(Instant.now().minusSeconds(60));

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getSession(false)).isNull();
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(302);
    }

    private OAuth2AuthenticationToken authenticate(Instant expiresAt) {
        var token = new OidcIdToken("test-id-token", expiresAt.minusSeconds(7200), expiresAt,
                Map.of("sub", "test-user"));
        var principal = new DefaultOidcUser(List.of(), token);
        var authentication = new OAuth2AuthenticationToken(principal, List.of(), "entra");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }
}
