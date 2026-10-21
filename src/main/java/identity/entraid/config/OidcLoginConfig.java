package identity.entraid.config;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.web.client.RestClient;
import identity.entraid.mapping.AppRoleAuthoritiesMapper;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

@Configuration
@ConditionalOnProperty(name = "entra.login.enabled", havingValue = "true")
@EnableConfigurationProperties(EntraLoginProperties.class)
public class OidcLoginConfig {
    private static final Logger LOG = LoggerFactory.getLogger(OidcLoginConfig.class);

    @Bean
    ClientRegistrationRepository clientRegistrations(EntraIdProperties entra, EntraLoginProperties login) {
        String authority = "https://login.microsoftonline.com/" + entra.tenantId();
        // Fixed public-cloud endpoints avoid startup discovery and arbitrary endpoint configuration.
        // Spring's OIDC decoder still validates issuer, audience, timestamps and signature.
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("entra")
                .clientId(login.clientId()).clientSecret(login.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(login.redirectUri()).scope("openid", "profile")
                .authorizationUri(authority + "/oauth2/v2.0/authorize")
                .tokenUri(authority + "/oauth2/v2.0/token")
                .jwkSetUri(entra.jwkSetUri()).issuerUri(entra.issuer())
                .clientName("Microsoft Entra ID").build());
    }

    @Bean
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient() {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(5));
        factory.setReadTimeout(Duration.ofSeconds(5));
        var client = new RestClientAuthorizationCodeTokenResponseClient();
        client.setRestClient(RestClient.builder().requestFactory(factory)
                .messageConverters(converters -> {
                    converters.clear();
                    converters.add(new FormHttpMessageConverter());
                    converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
                })
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler()).build());
        return client;
    }

    @Bean
    @Order(2)
    SecurityFilterChain oidcSecurity(HttpSecurity http, ClientRegistrationRepository registrations,
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient) throws Exception {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(builder -> {
            OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
            LOG.info("security_event=oidc_login_started");
        });
        return http
                .csrf(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(fixation -> fixation.changeSessionId()))
                // Fixed landing page prevents saving callback parameters or untrusted redirect targets.
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth2/authorization/entra", "/login/oauth2/code/entra").permitAll()
                        .requestMatchers(HttpMethod.GET, "/private", "/csrf").authenticated()
                        .requestMatchers(HttpMethod.GET, "/admin/test").hasAuthority(AppRoleAuthoritiesMapper.ADMIN)
                        .anyRequest().denyAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/entra"))
                        .accessDeniedHandler((request, response, exception) -> {
                            LOG.info("security_event=oidc_access_denied");
                            response.setStatus(403);
                        }))
                .oauth2Login(login -> login
                        .authorizedClientRepository(new HttpSessionOAuth2AuthorizedClientRepository())
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver))
                        .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(tokenClient))
                        .userInfoEndpoint(info -> info.userAuthoritiesMapper(new AppRoleAuthoritiesMapper()))
                        .successHandler((request, response, authentication) -> {
                            LOG.info("security_event=oidc_login_succeeded");
                            response.sendRedirect(request.getContextPath() + "/private");
                        })
                        .failureHandler((request, response, exception) -> {
                            LOG.warn("security_event=oidc_login_failed");
                            response.setStatus(401);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"authentication_failed\"}");
                        }))
                .logout(logout -> logout.logoutUrl("/logout").invalidateHttpSession(true)
                        .clearAuthentication(true).deleteCookies("JSESSIONID")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            LOG.info("security_event=oidc_logout");
                            response.setStatus(204);
                        }))
                .addFilterBefore(new OidcSessionExpiryFilter(), AuthorizationFilter.class)
                .build();
    }

    @Bean
    ServletListenerRegistrationBean<HttpSessionListener> sessionLifecycleListener() {
        return new ServletListenerRegistrationBean<>(new HttpSessionListener() {
            @Override
            public void sessionDestroyed(HttpSessionEvent event) {
                LOG.info("security_event=session_destroyed");
            }
        });
    }
}
