package de.palsoftware.scim.server.impl.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.task.SyncTaskExecutor;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
            savedEvent.setOperation(event.getOperation());
            return event;
        });

        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        UUID txnId = service.submitAsync(
                workspaceId,
                "POST",
                "User",
                null,
                baseUrl,
                () -> Map.of("id", newUserId.toString(), "userName", "async.user", "password", "secret")
        );

        assertNotNull(txnId);
        verify(asyncEventRepository).saveAndFlush(any(ScimAsyncEvent.class));
        verify(asyncEventRepository, atLeastOnce()).save(savedEvent);

        assertEquals("COMPLETED", savedEvent.getStatus());
        assertEquals("POST", savedEvent.getOperation());
        assertNotNull(savedEvent.getCompletedAt());
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
        // Updated per RFC 9967 §2.5.1.3 & §2.4.1: carries misc:asyncresp + prov:create:full with "data" wrapper
        assertTrue(events.containsKey(ScimAsyncEventService.ASYNC_RESP_EVENT_URI));
        Map<String, Object> asyncResp = (Map<String, Object>) events.get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
        assertEquals("201", asyncResp.get("status"));
        assertEquals("POST", asyncResp.get("method"));
        assertEquals(baseUrl + "/Users/" + newUserId, asyncResp.get("location"));

        assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:create:full"));
        Map<String, Object> createPayload = (Map<String, Object>) events.get("urn:ietf:params:scim:event:prov:create:full");
        Map<String, Object> data = (Map<String, Object>) createPayload.get("data");
        assertNotNull(data);
        assertEquals(newUserId.toString(), data.get("id"));
        assertFalse(data.containsKey("password"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSubmitAsync_FailureStoresErrorSet() throws Exception {
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";
        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(invocation -> {
            ScimAsyncEvent event = invocation.getArgument(0);
            savedEvent.setTxnId(event.getTxnId());
            savedEvent.setOperation(event.getOperation());
            return event;
        });
        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        UUID txnId = service.submitAsync(
                workspaceId,
                "POST",
                "User",
                null,
                baseUrl,
                () -> { throw new ScimException(409, "uniqueness", "Duplicate userName"); }
        );

        assertNotNull(txnId);
        assertEquals("FAILED", savedEvent.getStatus());
        assertEquals("POST", savedEvent.getOperation());
        assertNotNull(savedEvent.getCompletedAt());
        assertNotNull(savedEvent.getSetPayload());

        Map<String, Object> set = objectMapper.readValue(savedEvent.getSetPayload(), new TypeReference<>() {});
        assertEquals(txnId.toString(), set.get("txn"));
        Map<String, Object> events = (Map<String, Object>) set.get("events");
        Map<String, Object> asyncResp = (Map<String, Object>) events.get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
        assertEquals("409", asyncResp.get("status"));
        assertEquals("POST", asyncResp.get("method"));
        Map<String, Object> resp = (Map<String, Object>) asyncResp.get("response");
        assertEquals("409", resp.get("status"));
        assertEquals("uniqueness", resp.get("scimType"));
        assertTrue(resp.get("detail").toString().contains("Duplicate userName"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testBuildSetPayload_DeleteAndPatchNotice() throws Exception {
        UUID resId = UUID.randomUUID();
        UUID txnId = UUID.randomUUID();
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";

        // Updated per RFC 9967 §2.4.4: delete event MUST NOT carry :full or :notice suffix
        String deleteJson = service.buildSetPayload(baseUrl, txnId, "DELETE", "Group", resId, Map.of("id", resId.toString()));
        Map<String, Object> deleteSet = objectMapper.readValue(deleteJson, new TypeReference<>() {});
        Map<String, Object> delAsyncResp = (Map<String, Object>) ((Map<String, Object>) deleteSet.get("events")).get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
        assertEquals("204", delAsyncResp.get("status"));
        assertEquals("DELETE", delAsyncResp.get("method"));
        Map<String, Object> delEvents = (Map<String, Object>) deleteSet.get("events");
        assertTrue(delEvents.containsKey("urn:ietf:params:scim:event:prov:delete"));
        assertFalse(delEvents.containsKey("urn:ietf:params:scim:event:prov:delete:full"));

        // RFC 9967 §2.2 / §2.4.3: patch:notice emits modified attribute paths
        String patchJson = service.buildSetPayload(
                baseUrl, txnId, "PATCH", "User", resId,
                Map.of("id", resId.toString(), "displayName", "Alice"),
                List.of("displayName", "emails.value"));
        Map<String, Object> patchSet = objectMapper.readValue(patchJson, new TypeReference<>() {});
        Map<String, Object> patchAsyncResp = (Map<String, Object>) ((Map<String, Object>) patchSet.get("events")).get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
        assertEquals("200", patchAsyncResp.get("status"));
        assertEquals("PATCH", patchAsyncResp.get("method"));
        Map<String, Object> patchEvents = (Map<String, Object>) patchSet.get("events");
        Map<String, Object> notice = (Map<String, Object>) patchEvents.get("urn:ietf:params:scim:event:prov:patch:notice");
        assertNotNull(notice);
        assertEquals(List.of("displayName", "emails.value"), notice.get("attributes"));
        assertFalse(notice.containsKey("data"));

        // PUT maps to prov:put:full and status 200
        String putJson = service.buildSetPayload(
                baseUrl, txnId, "PUT", "User", resId,
                Map.of("id", resId.toString(), "displayName", "Alice Put"));
        Map<String, Object> putSet = objectMapper.readValue(putJson, new TypeReference<>() {});
        Map<String, Object> putAsyncResp = (Map<String, Object>) ((Map<String, Object>) putSet.get("events")).get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
        assertEquals("200", putAsyncResp.get("status"));
        assertEquals("PUT", putAsyncResp.get("method"));
        Map<String, Object> putEvents = (Map<String, Object>) putSet.get("events");
        assertTrue(putEvents.containsKey("urn:ietf:params:scim:event:prov:put:full"));
    }

    @Test
    void testGetEventAndAwaitNoOpWhenNotInFlight() {
        UUID txnId = UUID.randomUUID();
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        when(asyncEventRepository.findByTxnIdAndWorkspaceId(eq(txnId), eq(workspaceId))).thenReturn(Optional.of(event));

        service.awaitIfInFlight(txnId, Duration.ofMillis(50));
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

    @Test
    void testSubmitAsync_ExecutorRejection_MarksFlushedPendingEventFailedAndRethrows() {
        org.springframework.core.task.TaskRejectedException rejection =
                new org.springframework.core.task.TaskRejectedException("Queue full");
        ScimAsyncEventService rejectingService = new ScimAsyncEventService(
                asyncEventRepository,
                workspaceRepository,
                objectMapper,
                task -> {
                    throw rejection;
                }
        );

        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(inv -> {
            ScimAsyncEvent ev = inv.getArgument(0);
            savedEvent.setTxnId(ev.getTxnId());
            savedEvent.setStatus(ev.getStatus());
            return ev;
        });
        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        org.springframework.core.task.TaskRejectedException thrown = assertThrows(
                org.springframework.core.task.TaskRejectedException.class,
                () -> rejectingService.submitAsync(
                        workspaceId,
                        "create",
                        "User",
                        null,
                        "http://localhost:8080/ws/" + workspaceId + "/scim/v2",
                        () -> Map.of("userName", "never-runs")));

        assertSame(rejection, thrown);
        assertEquals("FAILED", savedEvent.getStatus());
        assertNotNull(savedEvent.getSetPayload());
        verify(asyncEventRepository).save(savedEvent);
    }

    @Test
    void testSubmitAsync_WorkerThrowsError_MarksEventFailedBeforeRethrowingError() {
        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(inv -> {
            ScimAsyncEvent ev = inv.getArgument(0);
            savedEvent.setTxnId(ev.getTxnId());
            savedEvent.setStatus(ev.getStatus());
            return ev;
        });
        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        AssertionError boom = new AssertionError("worker assertion failure");
        AssertionError thrown = assertThrows(
                AssertionError.class,
                () -> service.submitAsync(
                        workspaceId,
                        "create",
                        "User",
                        null,
                        "http://localhost:8080/ws/" + workspaceId + "/scim/v2",
                        () -> {
                            throw boom;
                        }));

        assertSame(boom, thrown);
        assertEquals("FAILED", savedEvent.getStatus());
        assertNotNull(savedEvent.getSetPayload());
        // Marked FAILED exactly once (not duplicated by outer catch)
        verify(asyncEventRepository, times(1)).save(savedEvent);
    }

    @Test
    void testCanonicalizeOperation_Valid() {
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("POST"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("post"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("create"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("CREATE"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("  create  "));
        assertEquals("PUT", ScimAsyncEventService.canonicalizeOperation("PUT"));
        assertEquals("PUT", ScimAsyncEventService.canonicalizeOperation("put"));
        assertEquals("PUT", ScimAsyncEventService.canonicalizeOperation("  put  "));
        assertEquals("PATCH", ScimAsyncEventService.canonicalizeOperation("PATCH"));
        assertEquals("PATCH", ScimAsyncEventService.canonicalizeOperation("patch"));
        assertEquals("DELETE", ScimAsyncEventService.canonicalizeOperation("DELETE"));
        assertEquals("DELETE", ScimAsyncEventService.canonicalizeOperation("delete"));
    }

    @Test
    void testCanonicalizeOperation_CaseVariationsAndWhitespaceStress() {
        // Mixed-case and whitespace variations
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("cReAtE"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("PoSt"));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation("   cReAtE \t\n  "));
        assertEquals("POST", ScimAsyncEventService.canonicalizeOperation(" \t PoSt \r\n "));
        assertEquals("PUT", ScimAsyncEventService.canonicalizeOperation("pUt"));
        assertEquals("PUT", ScimAsyncEventService.canonicalizeOperation("   \t pUt \n  "));
        assertEquals("PATCH", ScimAsyncEventService.canonicalizeOperation("pAtCh"));
        assertEquals("PATCH", ScimAsyncEventService.canonicalizeOperation(" \r\n  pAtCh \t "));
        assertEquals("DELETE", ScimAsyncEventService.canonicalizeOperation("dElEtE"));
        assertEquals("DELETE", ScimAsyncEventService.canonicalizeOperation("   \n dElEtE \t\r "));
    }

    @Test
    void testCanonicalizeOperation_InvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation(null));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation(""));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("   "));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation(" \t \n \r "));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("GET"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("HEAD"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("OPTIONS"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("CONNECT"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("TRACE"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("   OPTIONS   "));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("POSTING"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("PATCHWORK"));
        assertThrows(IllegalArgumentException.class, () -> ScimAsyncEventService.canonicalizeOperation("1234"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testBuildSetPayload_MiscAsyncRespAlwaysIncludesMethodMatchingCanonicalOperation() throws Exception {
        UUID resId = UUID.randomUUID();
        UUID txnId = UUID.randomUUID();
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";

        Map<String, String> opExpectedMethod = Map.of(
                "POST", "POST",
                "create", "POST",
                "cReAtE", "POST",
                "  PoSt  ", "POST",
                "PUT", "PUT",
                "pUt", "PUT",
                "PATCH", "PATCH",
                "pAtCh", "PATCH",
                "DELETE", "DELETE",
                "dElEtE", "DELETE"
        );

        for (Map.Entry<String, String> entry : opExpectedMethod.entrySet()) {
            String rawOp = entry.getKey();
            String expectedMethod = entry.getValue();

            String json = service.buildSetPayload(baseUrl, txnId, rawOp, "User", resId, Map.of("id", resId.toString()));
            Map<String, Object> set = objectMapper.readValue(json, new TypeReference<>() {});
            Map<String, Object> events = (Map<String, Object>) set.get("events");
            assertNotNull(events, "Events object must be present for op: " + rawOp);

            Map<String, Object> asyncResp = (Map<String, Object>) events.get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
            assertNotNull(asyncResp, "misc:asyncresp must be present for op: " + rawOp);
            assertEquals(expectedMethod, asyncResp.get("method"), "misc:asyncresp.method must match canonical op");

            if ("POST".equals(expectedMethod)) {
                assertEquals("201", asyncResp.get("status"), "POST must map to HTTP 201");
                assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:create:full"),
                        "POST must contain urn:ietf:params:scim:event:prov:create:full");
            } else if ("DELETE".equals(expectedMethod)) {
                assertEquals("204", asyncResp.get("status"), "DELETE must map to HTTP 204");
                assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:delete"),
                        "DELETE must contain urn:ietf:params:scim:event:prov:delete");
            } else if ("PUT".equals(expectedMethod)) {
                assertEquals("200", asyncResp.get("status"), "PUT must map to HTTP 200");
                assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:put:full"),
                        "PUT must contain urn:ietf:params:scim:event:prov:put:full");
            } else if ("PATCH".equals(expectedMethod)) {
                assertEquals("200", asyncResp.get("status"), "PATCH must map to HTTP 200");
                assertTrue(events.containsKey("urn:ietf:params:scim:event:prov:patch:full") || events.containsKey("urn:ietf:params:scim:event:prov:patch:notice"),
                        "PATCH must contain patch:full or patch:notice");
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void testBuildErrorSetPayloadSafe_IncludesMethodMatchingCanonicalOperation() throws Exception {
        UUID resId = UUID.randomUUID();
        UUID txnId = UUID.randomUUID();
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";

        Map<String, String> opExpectedMethod = Map.of(
                "POST", "POST",
                "create", "POST",
                "cReAtE", "POST",
                "PUT", "PUT",
                "pUt", "PUT",
                "PATCH", "PATCH",
                "DELETE", "DELETE"
        );

        for (Map.Entry<String, String> entry : opExpectedMethod.entrySet()) {
            String rawOp = entry.getKey();
            String expectedMethod = entry.getValue();

            String json = service.buildErrorSetPayloadSafe(baseUrl, txnId, "User", resId, rawOp,
                    new ScimException(400, "invalidValue", "Bad input"));
            Map<String, Object> set = objectMapper.readValue(json, new TypeReference<>() {});
            Map<String, Object> events = (Map<String, Object>) set.get("events");
            assertNotNull(events);

            Map<String, Object> asyncResp = (Map<String, Object>) events.get(ScimAsyncEventService.ASYNC_RESP_EVENT_URI);
            assertNotNull(asyncResp);
            assertEquals("400", asyncResp.get("status"));
            assertEquals(expectedMethod, asyncResp.get("method"));

            Map<String, Object> resp = (Map<String, Object>) asyncResp.get("response");
            assertNotNull(resp);
            assertEquals("400", resp.get("status"));
            assertEquals("invalidValue", resp.get("scimType"));
        }
    }

    @Test
    void testSubmitAsync_LegacyCreate_CanonicalizedToPost() {
        String baseUrl = "http://localhost:8080/ws/" + workspaceId + "/scim/v2";
        ScimAsyncEvent savedEvent = new ScimAsyncEvent();
        savedEvent.setWorkspace(mockWorkspace);
        savedEvent.setCreatedAt(Instant.now());

        when(asyncEventRepository.saveAndFlush(any(ScimAsyncEvent.class))).thenAnswer(invocation -> {
            ScimAsyncEvent event = invocation.getArgument(0);
            savedEvent.setTxnId(event.getTxnId());
            savedEvent.setStatus(event.getStatus());
            savedEvent.setOperation(event.getOperation());
            return event;
        });
        when(asyncEventRepository.findById(any(UUID.class))).thenReturn(Optional.of(savedEvent));

        service.submitAsync(
                workspaceId,
                "create",
                "User",
                null,
                baseUrl,
                () -> Map.of("userName", "legacy.create")
        );

        assertEquals("POST", savedEvent.getOperation());
    }
}
