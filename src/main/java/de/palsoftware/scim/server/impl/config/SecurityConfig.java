package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.ActuatorApiKeyAuthFilter;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RequestResponseLoggingFilter loggingFilter;
    private final ThrottlingFilter throttlingFilter;
    private final ScimOperationMetricsFilter scimOperationMetricsFilter;
    private final BearerTokenAuthFilter bearerTokenAuthFilter;
    private final ActuatorApiKeyAuthFilter actuatorApiKeyAuthFilter;

    public SecurityConfig(WorkspaceTokenRepository tokenRepository,
                          WorkspaceRepository workspaceRepository,
                          ObjectMapper objectMapper,
                          RequestResponseLoggingFilter loggingFilter,
                          ObjectProvider<ThrottlingFilter> throttlingFilterProvider,
                          ScimOperationMetricsFilter scimOperationMetricsFilter,
                          @Value("${app.security.actuator.api-key:}") String actuatorApiKey,
                          @Value("${management.server.port:-1}") int managementPort,
                          @Value("${server.port:8080}") int serverPort) {
        this.loggingFilter = loggingFilter;
        this.throttlingFilter = throttlingFilterProvider.getIfAvailable();
        this.scimOperationMetricsFilter = scimOperationMetricsFilter;
        this.bearerTokenAuthFilter = new BearerTokenAuthFilter(tokenRepository, workspaceRepository, objectMapper);
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
        return request -> {
            String uri = request.getRequestURI();
            return uri != null && uri.startsWith("/ws/") && uri.contains("/scim/v2");
        };
    }

    private static RequestMatcher actuatorPaths() {
        return request -> {
            String uri = request.getRequestURI();
            return uri != null && ("/actuator".equals(uri) || uri.startsWith("/actuator/"));
        };
    }

    private static RequestMatcher errorPaths() {
        return request -> {
            String uri = request.getRequestURI();
            return "/error".equals(uri);
        };
    }

    @Bean
    @SuppressWarnings("java:S4502") // Stateless REST API authenticated via Bearer/API-key headers without session cookies
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers(scimPaths(), actuatorPaths(), errorPaths()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/actuator/**").authenticated()
                .requestMatchers(scimPaths()).permitAll() // Auth enforced by BearerTokenAuthFilter
                .requestMatchers(errorPaths()).permitAll()
                .anyRequest().denyAll()
            )
            .addFilterBefore(scimOperationMetricsFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(actuatorApiKeyAuthFilter, ScimOperationMetricsFilter.class)
            .addFilterAfter(bearerTokenAuthFilter, ActuatorApiKeyAuthFilter.class);

        if (throttlingFilter != null) {
            http.addFilterAfter(throttlingFilter, BearerTokenAuthFilter.class)
                .addFilterAfter(loggingFilter, ThrottlingFilter.class);
        } else {
            http.addFilterAfter(loggingFilter, BearerTokenAuthFilter.class);
        }

        return http.build();
    }

    @Bean
    @ConditionalOnBean(ThrottlingFilter.class)
    public FilterRegistrationBean<ThrottlingFilter> disableThrottlingFilterServletRegistration(
            ThrottlingFilter filter) {
        FilterRegistrationBean<ThrottlingFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<ScimOperationMetricsFilter> disableMetricsFilterServletRegistration(
            ScimOperationMetricsFilter filter) {
        FilterRegistrationBean<ScimOperationMetricsFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<RequestResponseLoggingFilter> disableLoggingFilterServletRegistration(
            RequestResponseLoggingFilter filter) {
        FilterRegistrationBean<RequestResponseLoggingFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
