package identity.entraid;

import java.util.Map;
import java.net.URI;
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
    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        return ResponseEntity.status(302).location(URI.create("/oauth2/authorization/entra")).build();
    }

    @GetMapping("/auth/me")
    public IdentityResponse me(@AuthenticationPrincipal OidcUser principal) {
        var token = principal.getIdToken();
        return new IdentityResponse(true, "Microsoft Entra ID", new UserIdentity(
                token.getFullName(), token.getEmail(), token.getSubject(), token.getClaimAsString("tid")));
    }

    public record IdentityResponse(boolean authenticated, String provider, UserIdentity user) { }
    public record UserIdentity(String name, String email, String subject, String tenantId) { }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }
}
