package identity.entraid;

import java.util.Map;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import identity.entraid.config.SessionLifetime;
import java.util.List;
import java.net.URI;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnProperty(name = "entra.login.enabled", havingValue = "true")
public class LoginController {
    @GetMapping("/")
    public ResponseEntity<Void> home() {
        return ResponseEntity.status(302).location(URI.create("/login")).build();
    }

    @GetMapping("/login")
    public ResponseEntity<?> login(@AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            return ResponseEntity.status(302).location(URI.create("/demo/index.html")).build();
        }
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML)
                .body(new ClassPathResource("static/demo/login.html"));
    }

    @GetMapping("/auth/me")
    public IdentityResponse me(@AuthenticationPrincipal OidcUser principal, HttpSession session) {
        var token = principal.getIdToken();
        var claims = token.getClaims();
        boolean groupOverage = Boolean.TRUE.equals(claims.get("hasgroups"))
                || "true".equals(claims.get("hasgroups"))
                || (claims.get("_claim_names") instanceof Map<?, ?> names && names.containsKey("groups"));
        String groupStatus = groupOverage ? "requires_graph"
                : claims.containsKey("groups") ? "included" : "not_provided";
        return new IdentityResponse(true, "Microsoft Entra ID", new UserIdentity(
                token.getFullName(), token.getEmail(), token.getSubject(), token.getClaimAsString("tid")),
                claims, new AccessDetails(strings(claims.get("groups")), strings(claims.get("roles")),
                        strings(claims.get("wids")), groupStatus),
                new SessionDetails(SessionLifetime.expiresAt(session), Instant.now()));
    }

    private static List<String> strings(Object value) {
        if (!(value instanceof List<?> values)) return List.of();
        return values.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }

    public record IdentityResponse(boolean authenticated, String provider, UserIdentity user,
                                   Map<String, Object> claims, AccessDetails access, SessionDetails session) { }
    public record SessionDetails(Instant expiresAt, Instant serverTime) { }
    public record AccessDetails(List<String> groups, List<String> roles,
                                List<String> directoryRoles, String groupsStatus) { }
    public record UserIdentity(String name, String email, String subject, String tenantId) { }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }
}
