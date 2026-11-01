package de.palsoftware.scim.server.impl.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.core.task.SyncTaskExecutor;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class ScimAsyncEventServiceTest {

    private ScimAsyncEventRepository asyncEventRepository;
    private WorkspaceRepository workspaceRepository;
    private ObjectMapper objectMapper;
    private ScimAsyncEventService service;

    private final UUID workspaceId = UUID.randomUUID();
    private Workspace mockWorkspace;

    @BeforeEach
    void setUp() {
        asyncEventRepository = Mockito.mock(ScimAsyncEventRepository.class);
        workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        objectMapper = new ObjectMapper();

        mockWorkspace = new Workspace();
        mockWorkspace.setId(workspaceId);
        mockWorkspace.setName("Test Workspace");

        when(workspaceRepository.getReferenceById(workspaceId)).thenReturn(mockWorkspace);

        // Use SyncTaskExecutor for deterministic unit testing
        service = new ScimAsyncEventService(
                asyncEventRepository,
                workspaceRepository,
                objectMapper,
                new SyncTaskExecutor()
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSubmitAsync_Success() throws Exception {
        UUID newUserId = UUID.randomUUID();
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";

        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(invocation -> {
            ScimAsyncEvent event = invocation.getArgument(0);
            savedEvent.setTxnId(event.getTxnId());
            savedEvent.setStatus(event.getStatus());
            return event;
        });

        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        UUID txnId = service.submitAsync(
                workspaceId,
                "create",
                "User",
                null,
                baseUrl,
                () -> Map.of("id", newUserId.toString(), "userName", "async.user")
        );

        assertNotNull(txnId);
        verify(asyncEventRepository).saveAndFlush(any(ScimAsyncEvent.class));
        verify(asyncEventRepository, atLeastOnce()).save(savedEvent);

        assertEquals("COMPLETED", savedEvent.getStatus());
        assertEquals(newUserId, savedEvent.getResourceId());
        assertNotNull(savedEvent.getSetPayload());

        Map<String, Object> set = objectMapper.readValue(savedEvent.getSetPayload(), new TypeReference<Map<String, Object>>() {});
        assertEquals(baseUrl, set.get("iss"));
        assertEquals(txnId.toString(), set.get("txn"));
        assertNotNull(set.get("jti"));
        assertNotNull(set.get("iat"));

        Map<String, Object> subId = (Map<String, Object>) set.get("sub_id");
        assertEquals("uri", subId.get("format"));
        assertEquals(baseUrl + "/Users/" + newUserId, subId.get("uri"));

        Map<String, Object> events = (Map<String, Object>) set.get("events");
        assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:create:full"));
    }

    @Test
    void testSubmitAsync_Failure() {
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";
        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(invocation -> {
            ScimAsyncEvent event = invocation.getArgument(0);
            savedEvent.setTxnId(event.getTxnId());
            return event;
        });
        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        UUID txnId = service.submitAsync(
                workspaceId,
                "create",
                "User",
                null,
                baseUrl,
                () -> { throw new RuntimeException("Database error"); }
        );

        assertNotNull(txnId);
        assertEquals("FAILED", savedEvent.getStatus());
        assertNotNull(savedEvent.getSetPayload());
        assertTrue(savedEvent.getSetPayload().contains("Database error"));
    }

    @Test
    void testBuildSetPayload_Delete() throws Exception {
        UUID resId = UUID.randomUUID();
        UUID txnId = UUID.randomUUID();
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";

        String json = service.buildSetPayload(baseUrl, txnId, "delete", "Group", resId, Map.of("id", resId.toString()));
        assertNotNull(json);
        assertTrue(json.contains("urn:ietf:params:scim:event:prov:delete:full"));
        assertTrue(json.contains(baseUrl + "/Groups/" + resId));
    }

    @Test
    void testGetEvent() {
        UUID txnId = UUID.randomUUID();
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        when(asyncEventRepository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        Optional<ScimAsyncEvent> result = service.getEvent(txnId, workspaceId);
        assertTrue(result.isPresent());
        assertEquals(txnId, result.get().getTxnId());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testAutowiredConstructorPresentAndResolvesObjectProvider() throws NoSuchMethodException {
        var ctor = ScimAsyncEventService.class.getConstructor(
                ScimAsyncEventRepository.class,
                WorkspaceRepository.class,
                ObjectMapper.class,
                org.springframework.beans.factory.ObjectProvider.class
        );
        assertTrue(ctor.isAnnotationPresent(org.springframework.beans.factory.annotation.Autowired.class));

        org.springframework.beans.factory.ObjectProvider<org.springframework.core.task.TaskExecutor> provider =
                Mockito.mock(org.springframework.beans.factory.ObjectProvider.class);
        when(provider.getIfAvailable(any())).thenReturn(new SyncTaskExecutor());

        ScimAsyncEventService autowiredService = new ScimAsyncEventService(
                asyncEventRepository,
                workspaceRepository,
                objectMapper,
                provider
        );
        assertNotNull(autowiredService);
        verify(provider).getIfAvailable(any());
    }
}
