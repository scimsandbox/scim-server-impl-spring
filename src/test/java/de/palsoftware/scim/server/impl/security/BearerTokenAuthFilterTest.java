package de.palsoftware.scim.server.impl.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
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
    }

    @Test
    void invalidWorkspaceId_Returns404_NoWwwAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/ws/not-a-uuid/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(404, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
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
        String body = response.getContentAsString();
        assertTrue(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
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
        Mockito.verify(filterChain).doFilter(request, response);
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
        String body = response.getContentAsString();
        assertTrue(body.contains("Token does not belong to this workspace"));
    }
}

