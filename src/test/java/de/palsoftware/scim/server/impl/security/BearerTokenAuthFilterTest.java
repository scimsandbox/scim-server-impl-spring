package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.metrics.ScimRequestMetricAttributes;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class BearerTokenAuthFilterTest {

    private WorkspaceTokenRepository tokenRepository;
    private BearerTokenAuthFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        tokenRepository = Mockito.mock(WorkspaceTokenRepository.class);
        filter = new BearerTokenAuthFilter(tokenRepository, new ObjectMapper());
        filterChain = Mockito.mock(FilterChain.class);
    }

    @Test
    void missingAuthorizationHeader_Returns401WithWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void invalidBearerToken_Returns401WithWwwAuthenticate() throws Exception {
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer invalid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void emptyBearerToken_Returns401WithWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer ");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void invalidWorkspaceId_Returns404_NoWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/not-a-uuid/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(404, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
    }

    @Test
    void nonScimPath_PassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void response401_ContainsScimErrorSchema() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + UUID.randomUUID() + "/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("application/scim+json;charset=UTF-8", response.getContentType());
        assertEquals("UTF-8", response.getCharacterEncoding());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assertTrue(body.contains("\"status\":\"401\""));
    }

    @Test
    void expiredToken_Returns401() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("Token has expired"));
    }

    @Test
    void validNonExpiredToken_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void caseInsensitiveBearerScheme_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        for (String prefix : new String[]{"bearer ", "BEARER ", "bEaReR "}) {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
            request.addHeader("Authorization", prefix + "some-valid-token");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertEquals(200, response.getStatus(), "Failed for scheme prefix: " + prefix);
            assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                    request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        }
    }

    @Test
    void tokenWithNullExpiresAt_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(workspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(null);

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void tokenBelongingToDifferentWorkspace_Returns401() throws Exception {
        UUID requestedWorkspaceId = UUID.randomUUID();
        UUID tokenWorkspaceId = UUID.randomUUID();
        Workspace ws = new Workspace();
        ws.setId(tokenWorkspaceId);

        WorkspaceToken wsToken = new WorkspaceToken();
        wsToken.setWorkspace(ws);
        wsToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.of(wsToken));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/" + requestedWorkspaceId + "/scim/v2/Users");
        request.addHeader("Authorization", "Bearer some-valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        String body = response.getContentAsString();
        assertTrue(body.contains("Token does not belong to this workspace"));
    }

    @Test
    void anonymousGetServiceProviderConfig_PassesThrough() throws Exception {
        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId.toString(), request.getAttribute("WORKSPACE_ID"));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }

    @Test
    void invalidTokenOnServiceProviderConfig_StillReturns401() throws Exception {
        when(tokenRepository.findByTokenHashAndNotRevoked(anyString())).thenReturn(Optional.empty());

        UUID workspaceId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        request.addHeader("Authorization", "Bearer invalid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
    }

    @Test
    void anonymousGetServiceProviderConfig_NonExistentWorkspace_Returns404() throws Exception {
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        UUID unknownWorkspaceId = UUID.randomUUID();
        when(workspaceRepository.existsById(unknownWorkspaceId)).thenReturn(false);

        BearerTokenAuthFilter wsFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + unknownWorkspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse response = new MockHttpServletResponse();

        wsFilter.doFilter(request, response, filterChain);

        assertEquals(404, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertNull(request.getAttribute("WORKSPACE_ID"));
        assertEquals(ScimRequestMetricAttributes.AUTH_FAILED,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        assertTrue(response.getContentAsString().contains("Workspace not found"));
        Mockito.verifyNoInteractions(filterChain);
    }

    @Test
    void anonymousGetServiceProviderConfig_ExistingWorkspace_PassesThrough() throws Exception {
        WorkspaceRepository workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        UUID workspaceId = UUID.randomUUID();
        when(workspaceRepository.existsById(workspaceId)).thenReturn(true);

        BearerTokenAuthFilter wsFilter = new BearerTokenAuthFilter(
                tokenRepository, workspaceRepository, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "/ws/" + workspaceId + "/scim/v2/ServiceProviderConfig");
        MockHttpServletResponse response = new MockHttpServletResponse();

        wsFilter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
        assertEquals(workspaceId.toString(), request.getAttribute("WORKSPACE_ID"));
        assertEquals(ScimRequestMetricAttributes.AUTH_OK,
                request.getAttribute(ScimRequestMetricAttributes.AUTHENTICATION));
        Mockito.verify(filterChain).doFilter(request, response);
    }
}
