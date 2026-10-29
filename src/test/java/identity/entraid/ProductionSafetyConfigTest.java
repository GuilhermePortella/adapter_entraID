package identity.entraid;

import identity.entraid.config.ProductionSafetyConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class ProductionSafetyConfigTest {
    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(ProductionSafetyConfig.class)
            .withPropertyValues("spring.profiles.active=prod",
                    "entra.login.redirect-uri=https://portal.example.com/login/oauth2/code/entra");

    @Test
    void acceptsProductionDefaultsWithHttpsCallback() {
        context.run(app -> assertThat(app).hasNotFailed());
    }

    @Test
    void importsSecretFromMountedDirectory(@TempDir Path directory) throws Exception {
        Files.writeString(directory.resolve("entra.login.client-secret"), "fixture-secret-only");
        context.withPropertyValues("SECRETS_DIRECTORY=" + directory + "/").run(app -> {
            assertThat(app).hasNotFailed();
            assertThat(app.getEnvironment().getProperty("entra.login.client-secret"))
                    .isEqualTo("fixture-secret-only");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "server.ssl.enabled=false",
            "server.servlet.session.cookie.secure=false",
            "SESSION_COOKIE_SECURE=false",
            "server.servlet.session.cookie.http-only=false",
            "server.forward-headers-strategy=framework",
            "entra.login.redirect-uri=http://portal.example.com/login/oauth2/code/entra",
            "entra.login.redirect-uri=https://localhost/login/oauth2/code/entra",
            "entra.login.redirect-uri=",
            "spring.profiles.active=prod,local",
            "spring.profiles.active=local,prod"
    })
    void rejectsUnsafeProductionOverrides(String override) {
        context.withPropertyValues(override).run(app -> assertThat(app).hasFailed());
    }

    @Test
    void noExplicitProfileUsesProductionSafety() {
        new ApplicationContextRunner()
                .withInitializer(new ConfigDataApplicationContextInitializer())
                .withUserConfiguration(ProductionSafetyConfig.class)
                .withPropertyValues("server.ssl.enabled=false")
                .run(app -> assertThat(app).hasFailed());
    }

    @Test
    void localDefaultsAllowLoopbackHttpWithoutProductionGuard() {
        context.withPropertyValues("spring.profiles.active=local").run(app -> {
            assertThat(app).hasNotFailed().doesNotHaveBean(ProductionSafetyConfig.class);
            assertThat(app.getEnvironment().getProperty("server.address")).isEqualTo("127.0.0.1");
            assertThat(app.getEnvironment().getProperty("server.ssl.enabled")).isEqualTo("false");
        });
    }
}
