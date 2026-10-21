package identity.entraid;

import identity.entraid.mapping.AppRoleAuthoritiesMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import static org.assertj.core.api.Assertions.assertThat;

class AppRoleAuthoritiesMapperTest {
    private final AppRoleAuthoritiesMapper mapper = new AppRoleAuthoritiesMapper();

    @Test
    void mapsOnlyAllowlistedRoleFromIdTokenAndPreservesOrdinaryAuthorities() {
        var idToken = token(Map.of("sub", "user", "roles", List.of("Gateway.AdminGlobal", "Other.Role")));
        var result = mapper.mapAuthorities(List.of(new OidcUserAuthority(idToken),
                new SimpleGrantedAuthority("SCOPE_openid")));
        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("OIDC_USER", "SCOPE_openid", AppRoleAuthoritiesMapper.ADMIN);
    }

    @Test
    void userInfoAndPrebuiltAppRoleCannotGrantAdministrativeAuthority() {
        var authority = new OidcUserAuthority(token(Map.of("sub", "user")),
                new OidcUserInfo(Map.of("sub", "user", "roles", List.of("Gateway.AdminGlobal"))));
        var result = mapper.mapAuthorities(List.of(authority,
                new SimpleGrantedAuthority(AppRoleAuthoritiesMapper.ADMIN)));
        assertThat(result).extracting(GrantedAuthority::getAuthority).containsExactly("OIDC_USER");
    }

    private OidcIdToken token(Map<String, Object> claims) {
        return new OidcIdToken("test-only", Instant.now(), Instant.now().plusSeconds(300), claims);
    }
}
