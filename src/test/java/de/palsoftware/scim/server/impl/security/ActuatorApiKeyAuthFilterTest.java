package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class ActuatorApiKeyAuthFilterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        filterChain = Mockito.mock(FilterChain.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void healthAndProbes_AlwaysPassThrough_PopulatingPrincipalOnlyWhenAuthorized() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("super-secret-key", 9090, 8080, objectMapper);

        // 1. Unauthenticated /actuator/health passes through with anonymous/null context
        MockHttpServletRequest unauthHealth = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse unauthResp = new MockHttpServletResponse();
        AtomicReference<Authentication> observedUnauth = new AtomicReference<>();
        FilterChain capturingChain = (req, res) -> observedUnauth.set(SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(unauthHealth, unauthResp, capturingChain);
        assertThat(unauthResp.getStatus()).isEqualTo(200);
        assertThat(observedUnauth.get()).isNull();

        // 2. Unauthenticated /actuator/health/readiness also passes through
        MockHttpServletRequest readinessReq = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        MockHttpServletResponse readinessResp = new MockHttpServletResponse();
        filter.doFilter(readinessReq, readinessResp, filterChain);
        assertThat(readinessResp.getStatus()).isEqualTo(200);
        verify(filterChain).doFilter(readinessReq, readinessResp);

        // 3. Authenticated /actuator/health sets ROLE_ACTUATOR so show-components=when_authorized works
        MockHttpServletRequest authHealth = new MockHttpServletRequest("GET", "/actuator/health");
        authHealth.addHeader("X-API-Key", "super-secret-key");
        MockHttpServletResponse authResp = new MockHttpServletResponse();
        AtomicReference<Authentication> observedAuth = new AtomicReference<>();
        FilterChain authCapturingChain = (req, res) -> observedAuth.set(SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(authHealth, authResp, authCapturingChain);
        assertThat(authResp.getStatus()).isEqualTo(200);
        assertThat(observedAuth.get()).isNotNull();
        assertThat(observedAuth.get().isAuthenticated()).isTrue();
    }

    @Test
    void nonHealthActuator_WhenApiKeyConfigured_EnforcesConstantTimeMatch() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("expected-api-key", 9090, 8080, objectMapper);

        // Missing API key -> 401 even on management port
        MockHttpServletRequest missingReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        missingReq.setLocalPort(9090);
        MockHttpServletResponse missingResp = new MockHttpServletResponse();
        filter.doFilter(missingReq, missingResp, filterChain);

        assertThat(missingResp.getStatus()).isEqualTo(401);
        assertThat(missingResp.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(missingResp.getContentAsString()).contains("\"status\":\"401\"");
        verifyNoInteractions(filterChain);

        // Wrong API key -> 401
        MockHttpServletRequest wrongReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        wrongReq.addHeader("X-API-Key", "wrong-key");
        MockHttpServletResponse wrongResp = new MockHttpServletResponse();
        filter.doFilter(wrongReq, wrongResp, filterChain);

        assertThat(wrongResp.getStatus()).isEqualTo(401);
        verifyNoInteractions(filterChain);

        // Matching X-API-Key -> passes through with authenticated principal
        SecurityContextHolder.clearContext();
        MockHttpServletRequest validXApiKey = new MockHttpServletRequest("GET", "/actuator/prometheus");
        validXApiKey.addHeader("X-API-Key", "expected-api-key");
        MockHttpServletResponse validResp1 = new MockHttpServletResponse();
        filter.doFilter(validXApiKey, validResp1, filterChain);

        assertThat(validResp1.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(validXApiKey, validResp1);

        // Matching Authorization: Bearer -> passes through
        SecurityContextHolder.clearContext();
        MockHttpServletRequest validBearer = new MockHttpServletRequest("GET", "/actuator/prometheus");
        validBearer.addHeader("Authorization", "bearer expected-api-key");
        MockHttpServletResponse validResp2 = new MockHttpServletResponse();
        filter.doFilter(validBearer, validResp2, filterChain);

        assertThat(validResp2.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(validBearer, validResp2);
    }

    @Test
    void nonHealthActuator_WhenApiKeyBlank_PermitsOnlyDedicatedManagementPort() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("", 9090, 8080, objectMapper);

        // Request on main SCIM port (8080) -> denied (403)
        MockHttpServletRequest mainPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        mainPortReq.setLocalPort(8080);
        MockHttpServletResponse mainPortResp = new MockHttpServletResponse();
        filter.doFilter(mainPortReq, mainPortResp, filterChain);

        assertThat(mainPortResp.getStatus()).isEqualTo(403);
        assertThat(mainPortResp.getContentAsString()).contains("\"status\":\"403\"");
        verifyNoInteractions(filterChain);

        // Request on dedicated management port (9090) -> allowed
        MockHttpServletRequest mgmtPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        mgmtPortReq.setLocalPort(9090);
        MockHttpServletResponse mgmtPortResp = new MockHttpServletResponse();
        filter.doFilter(mgmtPortReq, mgmtPortResp, filterChain);

        assertThat(mgmtPortResp.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(mgmtPortReq, mgmtPortResp);

        // Same port configured for both server and management -> denied even on 8080
        SecurityContextHolder.clearContext();
        ActuatorApiKeyAuthFilter sharedPortFilter = new ActuatorApiKeyAuthFilter("   ", 8080, 8080, objectMapper);
        MockHttpServletRequest sharedPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        sharedPortReq.setLocalPort(8080);
        MockHttpServletResponse sharedPortResp = new MockHttpServletResponse();
        FilterChain chain2 = Mockito.mock(FilterChain.class);
        sharedPortFilter.doFilter(sharedPortReq, sharedPortResp, chain2);

        assertThat(sharedPortResp.getStatus()).isEqualTo(403);
        verifyNoInteractions(chain2);

        // Dynamic runtime port (0 -> 54321) -> allowed on 54321, denied on 54320
        ActuatorApiKeyAuthFilter dynamicFilter = new ActuatorApiKeyAuthFilter("", 0, 0, objectMapper);
        dynamicFilter.updateRuntimePort(null, 54320);
        dynamicFilter.updateRuntimePort("management", 54321);

        MockHttpServletRequest dynMain = new MockHttpServletRequest("GET", "/actuator/prometheus");
        dynMain.setLocalPort(54320);
        MockHttpServletResponse dynMainResp = new MockHttpServletResponse();
        FilterChain chain3 = Mockito.mock(FilterChain.class);
        dynamicFilter.doFilter(dynMain, dynMainResp, chain3);
        assertThat(dynMainResp.getStatus()).isEqualTo(403);
        verifyNoInteractions(chain3);

        MockHttpServletRequest dynMgmt = new MockHttpServletRequest("GET", "/actuator/prometheus");
        dynMgmt.setLocalPort(54321);
        MockHttpServletResponse dynMgmtResp = new MockHttpServletResponse();
        dynamicFilter.doFilter(dynMgmt, dynMgmtResp, chain3);
        assertThat(dynMgmtResp.getStatus()).isEqualTo(200);
        verify(chain3).doFilter(dynMgmt, dynMgmtResp);
    }

    @Test
    void nonActuatorEndpoints_AreSkipped() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("secret", 9090, 8080, objectMapper);
        MockHttpServletRequest scimReq = new MockHttpServletRequest("GET", "/ws/123/scim/v2/Users");
        MockHttpServletResponse scimResp = new MockHttpServletResponse();

        filter.doFilter(scimReq, scimResp, filterChain);

        assertThat(scimResp.getStatus()).isEqualTo(200);
        verify(filterChain).doFilter(scimReq, scimResp);
    }
}
