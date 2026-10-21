package identity.entraid.mapping;

import java.util.Collection;
import java.util.HashSet;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

public final class AppRoleAuthoritiesMapper implements GrantedAuthoritiesMapper {
    public static final String ADMIN = "APPROLE_Gateway.AdminGlobal";

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        var mapped = new HashSet<GrantedAuthority>();
        for (GrantedAuthority authority : authorities) {
            // Never accept an APPROLE supplied by another source (e.g. UserInfo).
            if (!authority.getAuthority().startsWith("APPROLE_")) {
                mapped.add(authority);
            }
            if (authority instanceof OidcUserAuthority oidc) {
                Object roles = oidc.getIdToken().getClaims().get("roles");
                if (roles instanceof Collection<?> values && values.contains("Gateway.AdminGlobal")) {
                    mapped.add(new SimpleGrantedAuthority(ADMIN));
                }
            }
        }
        return mapped;
    }
}
