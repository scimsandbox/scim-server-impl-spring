package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.PayloadSizeLimitFilter;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.filter.WorkspaceRateLimitFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.ActuatorApiKeyAuthFilter;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final BearerTokenAuthFilter bearerTokenAuthFilter;
    private final ActuatorApiKeyAuthFilter actuatorApiKeyAuthFilter;

    public SecurityConfig(
            WorkspaceTokenRepository tokenRepository,
            WorkspaceRepository workspaceRepository,
            ObjectMapper objectMapper,
            Environment environment,
            ObjectProvider<ThrottlingFilter.UnauthenticatedLookupLimiter> unauthenticatedLookupLimiterProvider) {
        Binder binder = Binder.get(environment);
        boolean rateLimitEnabled = binder.bind("app.rate-limit.enabled", Boolean.class).orElse(false);
        String actuatorApiKey = environment.getProperty("app.security.actuator.api-key", "");
        int managementPort = binder.bind("management.server.port", Integer.class).orElse(-1);
        int serverPort = binder.bind("server.port", Integer.class).orElse(8080);

        ThrottlingFilter.UnauthenticatedLookupLimiter lookupLimiter = rateLimitEnabled
                ? unauthenticatedLookupLimiterProvider.getIfAvailable(
                        () -> ThrottlingFilter.createUnauthenticatedLookupLimiter(environment))
                : ThrottlingFilter.UnauthenticatedLookupLimiter.NOOP;
        this.bearerTokenAuthFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, objectMapper, lookupLimiter);
        this.actuatorApiKeyAuthFilter = new ActuatorApiKeyAuthFilter(
                actuatorApiKey, managementPort, serverPort, objectMapper);
    }

    @EventListener(WebServerInitializedEvent.class)
    public void onWebServerInitialized(WebServerInitializedEvent event) {
        actuatorApiKeyAuthFilter.updateRuntimePort(
                event.getApplicationContext().getServerNamespace(),
                event.getWebServer().getPort());
    }

    private static RequestMatcher scimPaths() {
        return RequestPaths::isScimPath;
    }

    private static RequestMatcher actuatorPaths() {
        return RequestPaths::isActuatorPath;
    }

    private static RequestMatcher errorPaths() {
        return request -> {
            String uri = request.getRequestURI();
            return "/error".equals(uri);
        };
    }

    @Bean
    @SuppressWarnings("java:S4502") // Stateless REST API authenticated via Bearer/API-key headers without session cookies
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ScimOperationMetricsFilter scimOperationMetricsFilter,
            ObjectProvider<ThrottlingFilter> throttlingFilterProvider,
            ObjectProvider<WorkspaceRateLimitFilter> workspaceRateLimitFilterProvider,
            RequestResponseLoggingFilter loggingFilter,
            PayloadSizeLimitFilter payloadSizeLimitFilter) throws Exception {
        ThrottlingFilter throttlingFilter = throttlingFilterProvider.getIfAvailable();
        WorkspaceRateLimitFilter workspaceRateLimitFilter = workspaceRateLimitFilterProvider.getIfAvailable();

        http
            .csrf(csrf -> csrf.ignoringRequestMatchers(scimPaths(), actuatorPaths(), errorPaths()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers(actuatorPaths()).authenticated()
                .requestMatchers(scimPaths()).permitAll() // Auth enforced by BearerTokenAuthFilter
                .requestMatchers(errorPaths()).permitAll()
                .anyRequest().denyAll()
            )
            .addFilterBefore(scimOperationMetricsFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(actuatorApiKeyAuthFilter, ScimOperationMetricsFilter.class);

        if (throttlingFilter != null) {
            http.addFilterAfter(throttlingFilter, ActuatorApiKeyAuthFilter.class)
                .addFilterAfter(bearerTokenAuthFilter, ThrottlingFilter.class);
        } else {
            http.addFilterAfter(bearerTokenAuthFilter, ActuatorApiKeyAuthFilter.class);
        }

        if (workspaceRateLimitFilter != null) {
            http.addFilterAfter(workspaceRateLimitFilter, BearerTokenAuthFilter.class)
                .addFilterAfter(loggingFilter, WorkspaceRateLimitFilter.class);
        } else {
            http.addFilterAfter(loggingFilter, BearerTokenAuthFilter.class);
        }

        http.addFilterAfter(payloadSizeLimitFilter, RequestResponseLoggingFilter.class);

        return http.build();
    }
}
