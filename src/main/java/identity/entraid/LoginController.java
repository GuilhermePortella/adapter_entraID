package identity.entraid;

import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnProperty(name = "entra.login.enabled", havingValue = "true")
public class LoginController {
    @GetMapping("/private")
    public Map<String, String> authenticated() {
        return Map.of("status", "authenticated");
    }

    @GetMapping("/admin/test")
    public Map<String, String> admin() {
        return Map.of("status", "authorized");
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }
}
