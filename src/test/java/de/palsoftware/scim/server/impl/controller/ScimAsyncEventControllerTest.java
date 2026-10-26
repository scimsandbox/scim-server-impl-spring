package de.palsoftware.scim.server.impl.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class ScimAsyncEventControllerTest {

    private ScimAsyncEventRepository repository;
    private ObjectMapper objectMapper;
    private ScimAsyncEventController controller;
    private final UUID workspaceId = UUID.randomUUID();
    private final UUID txnId = UUID.randomUUID();
    private Workspace mockWorkspace;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        repository = Mockito.mock(ScimAsyncEventRepository.class);
        objectMapper = new ObjectMapper();
        controller = new ScimAsyncEventController(repository, objectMapper);

        mockWorkspace = new Workspace();
        mockWorkspace.setId(workspaceId);
        mockWorkspace.setName("Test Workspace");

        request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Events/" + txnId);
    }

    @Test
    void testGetEvent_Pending() {
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(mockWorkspace);
        event.setOperation("create");
        event.setResourceType("User");
        event.setStatus("PENDING");
        event.setCreatedAt(Instant.now());

        when(repository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        ResponseEntity<?> response = controller.getEvent(workspaceId.toString(), txnId.toString(), null, request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertEquals(txnId.toString(), response.getHeaders().getFirst(ScimPreferHeaderUtil.SET_TXN_HEADER));
        String expectedLocation = "http://localhost:8080/ws/" + workspaceId + "/scim/v2/Events/" + txnId;
        assertEquals(expectedLocation, response.getHeaders().getFirst("Location"));
        assertNull(response.getBody());
    }

    @Test
    void testGetEvent_Pending_Compat() {
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(mockWorkspace);
        event.setOperation("create");
        event.setResourceType("User");
        event.setStatus("PENDING");
        event.setCreatedAt(Instant.now());

        when(repository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        ResponseEntity<?> response = controller.getEvent(workspaceId.toString(), txnId.toString(), "ms", request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        String expectedLocation = "http://localhost:8080/ws/" + workspaceId + "/scim/v2/ms/Events/" + txnId;
        assertEquals(expectedLocation, response.getHeaders().getFirst("Location"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGetEvent_Completed() throws Exception {
        Map<String, Object> setJson = Map.of(
                "iss", "http://localhost:8080/ws/" + workspaceId + "/scim/v2",
                "iat", Instant.now().getEpochSecond(),
                "jti", UUID.randomUUID().toString(),
                "txn", txnId.toString(),
                "sub_id", Map.of("format", "uri", "uri", "http://localhost:8080/ws/" + workspaceId + "/scim/v2/Users/" + UUID.randomUUID()),
                "events", Map.of("urn:ietf:params:scim:event:prov:create:full", Map.of("userName", "alice"))
        );
        String payload = objectMapper.writeValueAsString(setJson);

        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(mockWorkspace);
        event.setOperation("create");
        event.setResourceType("User");
        event.setStatus("COMPLETED");
        event.setSetPayload(payload);
        event.setCreatedAt(Instant.now().minusSeconds(5));
        event.setCompletedAt(Instant.now());

        when(repository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        ResponseEntity<?> response = controller.getEvent(workspaceId.toString(), txnId.toString(), null, request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertEquals(txnId.toString(), body.get("txn"));
        assertTrue(body.containsKey("events"));
    }

    @Test
    void testGetEvent_NotFound() {
        when(repository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.empty());

        ScimException ex = assertThrows(ScimException.class, () ->
                controller.getEvent(workspaceId.toString(), txnId.toString(), null, request));
        assertEquals(404, ex.getHttpStatus());
    }

    @Test
    void testGetEvent_Failed() {
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(mockWorkspace);
        event.setStatus("FAILED");
        event.setSetPayload("User already exists");

        when(repository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        ScimException ex = assertThrows(ScimException.class, () ->
                controller.getEvent(workspaceId.toString(), txnId.toString(), null, request));
        assertEquals(500, ex.getHttpStatus());
    }

    @Test
    void testGetEvent_InvalidTxnId() {
        ScimException ex = assertThrows(ScimException.class, () ->
                controller.getEvent(workspaceId.toString(), "not-a-uuid", null, request));
        assertEquals(404, ex.getHttpStatus());
    }
}
