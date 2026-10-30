package identity.entraid.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/** Enforces an absolute deadline independently of user activity and browser timers. */
final class OidcSessionExpiryFilter extends OncePerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(OidcSessionExpiryFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser user) {
            Instant expiry = user.getIdToken().getExpiresAt();
            Instant deadline = SessionLifetime.expiresAt(request.getSession(false));
            Instant now = Instant.now();
            if (expiry == null || deadline == null || !now.isBefore(expiry) || !now.isBefore(deadline)) {
                new SecurityContextLogoutHandler().logout(request, response, authentication);
                LOG.info("security_event=oidc_session_expired");
                if (PageAccessDenied.isProtectedPage(request)) {
                    PageAccessDenied.respond(request, response);
                } else {
                    new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/entra")
                            .commence(request, response, null);
                }
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
