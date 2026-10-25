package identity.entraid.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.io.ClassPathResource;

/** Serves the denied page directly, preserving the HTTP status and security headers. */
final class PageAccessDenied {
    private PageAccessDenied() { }

    static boolean isProtectedPage(HttpServletRequest request) {
        return (request.getContextPath() + "/demo/index.html").equals(request.getRequestURI());
    }

    static void respond(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        if (!"HEAD".equals(request.getMethod())) {
            try (var body = new ClassPathResource("pages/403.html").getInputStream()) {
                body.transferTo(response.getOutputStream());
            }
        }
    }
}
