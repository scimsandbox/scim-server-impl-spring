package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final WorkspaceTokenRepository tokenRepository;
    private final ObjectMapper objectMapper;
    private final RequestResponseLoggingFilter loggingFilter;
    private final ThrottlingFilter throttlingFilter;

    public SecurityConfig(WorkspaceTokenRepository tokenRepository,
                          ObjectMapper objectMapper,
                          RequestResponseLoggingFilter loggingFilter,
                          ThrottlingFilter throttlingFilter) {
        this.tokenRepository = tokenRepository;
        this.objectMapper = objectMapper;
        this.loggingFilter = loggingFilter;
        this.throttlingFilter = throttlingFilter;
    }

    private RequestMatcher scimPaths() {
        return request -> {
            String uri = request.getRequestURI();
            return uri != null && uri.startsWith("/ws/") && uri.contains("/scim/v2");
        };
    }



    private RequestMatcher errorPaths() {
        return request -> {
            String uri = request.getRequestURI();
            return uri != null && uri.equals("/error");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF is safe to disable: SCIM endpoints are stateless APIs using bearer tokens, not browser sessions
            .csrf(csrf -> csrf.ignoringRequestMatchers(scimPaths(), errorPaths()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers(scimPaths()).permitAll() // Auth handled by our filter
                .requestMatchers(errorPaths()).permitAll() // Allow Spring Boot to render 404s cleanly
                .anyRequest().denyAll()
            )
            .addFilterBefore(bearerTokenAuthFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(throttlingFilter, BearerTokenAuthFilter.class)
            .addFilterAfter(loggingFilter, ThrottlingFilter.class);

        return http.build();
    }

    @Bean
    public BearerTokenAuthFilter bearerTokenAuthFilter() {
        return new BearerTokenAuthFilter(tokenRepository, objectMapper);
    }
}
