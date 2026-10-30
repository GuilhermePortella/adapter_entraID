package identity.entraid.config;

import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;

public final class SessionLifetime {
    public static final String EXPIRES_AT = SessionLifetime.class.getName() + ".expiresAt";
    public static final Duration MAX_AGE = Duration.ofMinutes(40);

    private SessionLifetime() { }

    public static void start(HttpSession session, Instant tokenExpiry) {
        Instant deadline = Instant.now().plus(MAX_AGE);
        session.setAttribute(EXPIRES_AT, tokenExpiry.isBefore(deadline) ? tokenExpiry : deadline);
        session.setMaxInactiveInterval((int) MAX_AGE.toSeconds());
    }

    public static Instant expiresAt(HttpSession session) {
        return session != null && session.getAttribute(EXPIRES_AT) instanceof Instant expiry ? expiry : null;
    }
}
