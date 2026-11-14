package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.PayloadSizeLimitFilter;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.ActuatorApiKeyAuthFilter;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.boot.web.server.WebServer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecurityConfigTest {

    @Configuration(proxyBeanMethods = false)
    static class TestSupportBeans {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        WorkspaceTokenRepository workspaceTokenRepository() {
            return Mockito.mock(WorkspaceTokenRepository.class);
        }

        @Bean
        WorkspaceRepository workspaceRepository() {
            return Mockito.mock(WorkspaceRepository.class);
        }

        @Bean
        ScimRequestLogRepository scimRequestLogRepository() {
            return Mockito.mock(ScimRequestLogRepository.class);
        }
    }

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withInitializer(ctx -> ctx.getBeanFactory()
                    .setConversionService(new ApplicationConversionService()))
            .withConfiguration(AutoConfigurations.of(
                    WebMvcAutoConfiguration.class,
                    SecurityAutoConfiguration.class))
            .withUserConfiguration(
                    TestSupportBeans.class,
                    ScimOperationMetricsFilter.class,
                    ThrottlingFilter.class,
                    PayloadSizeLimitFilter.class,
                    RequestResponseLoggingFilter.class,
                    SecurityConfig.class);

    @Test
    void securityFilterChain_WhenRateLimitEnabled_OrdersThrottlingBeforeBearerAndPayloadBeforeLogging() {
        contextRunner
                .withPropertyValues(
                        "app.rate-limit.enabled=true",
                        "app.rate-limit.requests-per-second=200",
                        "app.rate-limit.wait-timeout=0s",
                        "app.security.actuator.api-key=unit-test-key")
                .run(context -> {
                    assertThat(context.getBeansOfType(ThrottlingFilter.class)).hasSize(1);
                    assertThat(context.getBeansOfType(FilterRegistrationBean.class)).isEmpty();

                    SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
                    List<Class<?>> filterTypes = chain.getFilters().stream()
                            .<Class<?>>map(Filter::getClass)
                            .toList();

                    int metricsIdx = filterTypes.indexOf(ScimOperationMetricsFilter.class);
                    int actuatorIdx = filterTypes.indexOf(ActuatorApiKeyAuthFilter.class);
                    int throttlingIdx = filterTypes.indexOf(ThrottlingFilter.class);
                    int bearerIdx = filterTypes.indexOf(BearerTokenAuthFilter.class);
                    int payloadIdx = filterTypes.indexOf(PayloadSizeLimitFilter.class);
                    int loggingIdx = filterTypes.indexOf(RequestResponseLoggingFilter.class);

                    assertThat(metricsIdx).isGreaterThanOrEqualTo(0);
                    assertThat(actuatorIdx).isGreaterThan(metricsIdx);
                    assertThat(throttlingIdx).isGreaterThan(actuatorIdx);
                    assertThat(bearerIdx).isGreaterThan(throttlingIdx);
                    assertThat(payloadIdx).isGreaterThan(bearerIdx);
                    assertThat(loggingIdx).isGreaterThan(payloadIdx);

                    // Verify request matchers (scimPaths, actuatorPaths, errorPaths, denyAll)
                    Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
                    MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context)
                            .addFilters(springSecurityFilterChain)
                            .build();

                    mockMvc.perform(post("/ws/" + UUID.randomUUID() + "/scim/v2/Users")
                                    .contentType("application/scim+json")
                                    .content("{}"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(get("/actuator"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(get("/actuator")
                                    .header("X-API-Key", "unit-test-key"))
                            .andExpect(status().isNotFound());

                    mockMvc.perform(get("/actuator/prometheus"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(post("/error"))
                            .andExpect(status().isNotFound());

                    mockMvc.perform(get("/completely-unmapped"))
                            .andExpect(status().isForbidden());
                });
    }

    @Test
    void securityFilterChain_WhenRateLimitDisabled_OmitsThrottlingFilterAndUpdatesRuntimePort() {
        contextRunner
                .withPropertyValues("app.rate-limit.enabled=false")
                .run(context -> {
                    assertThat(context.getBeansOfType(ThrottlingFilter.class)).isEmpty();

                    SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
                    List<Class<?>> filterTypes = chain.getFilters().stream()
                            .<Class<?>>map(Filter::getClass)
                            .toList();

                    assertThat(filterTypes).doesNotContain(ThrottlingFilter.class);

                    int metricsIdx = filterTypes.indexOf(ScimOperationMetricsFilter.class);
                    int actuatorIdx = filterTypes.indexOf(ActuatorApiKeyAuthFilter.class);
                    int bearerIdx = filterTypes.indexOf(BearerTokenAuthFilter.class);
                    int payloadIdx = filterTypes.indexOf(PayloadSizeLimitFilter.class);
                    int loggingIdx = filterTypes.indexOf(RequestResponseLoggingFilter.class);

                    assertThat(actuatorIdx).isGreaterThan(metricsIdx);
                    assertThat(bearerIdx).isGreaterThan(actuatorIdx);
                    assertThat(payloadIdx).isGreaterThan(bearerIdx);
                    assertThat(loggingIdx).isGreaterThan(payloadIdx);

                    // Verify WebServerInitializedEvent listener forwards runtime ports cleanly
                    SecurityConfig securityConfig = context.getBean(SecurityConfig.class);
                    WebServer webServer = Mockito.mock(WebServer.class);
                    when(webServer.getPort()).thenReturn(19090);
                    WebServerApplicationContext wsContext = Mockito.mock(WebServerApplicationContext.class);
                    when(wsContext.getServerNamespace()).thenReturn("management");
                    WebServerInitializedEvent event = Mockito.mock(WebServerInitializedEvent.class);
                    when(event.getWebServer()).thenReturn(webServer);
                    when(event.getApplicationContext()).thenReturn(wsContext);

                    securityConfig.onWebServerInitialized(event);
                });
    }
}
