package de.palsoftware.scim.server.impl.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimAsyncEventStalePendingReaperServiceTest {

    @Mock
    private ScimAsyncEventRepository asyncEventRepository;

    @Mock
    private ScimAsyncEventService asyncEventService;

    private final TransactionOperations transactionOperations = new TransactionOperations() {
        @Override
        public <T> T execute(TransactionCallback<T> action) {
            return action.doInTransaction(new SimpleTransactionStatus());
        }

        @Override
        public void executeWithoutResult(java.util.function.Consumer<TransactionStatus> action) {
            action.accept(new SimpleTransactionStatus());
        }
    };

    private final ObjectMapper objectMapper = new ObjectMapper();

    private ScimAsyncEventStalePendingReaperService createService(boolean enabled, Duration timeout) {
        return new ScimAsyncEventStalePendingReaperService(
                asyncEventRepository, asyncEventService, transactionOperations, enabled, timeout);
    }

    private ScimAsyncEvent createPendingEvent(UUID txnId, String operation, String resourceType, UUID resourceId) {
        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        Workspace ws = new Workspace();
        ws.setId(UUID.randomUUID());
        event.setWorkspace(ws);
        event.setOperation(operation);
        event.setResourceType(resourceType);
        event.setResourceId(resourceId);
        event.setStatus("PENDING");
        event.setCreatedAt(Instant.now().minus(Duration.ofMinutes(10)));
        return event;
    }

    @Test
    void sweepStalePendingEventsOnSchedule_whenDisabled_doesNothing() {
        ScimAsyncEventStalePendingReaperService service = createService(false, Duration.ofMinutes(5));

        int count = service.sweepStalePendingEventsOnSchedule();

        assertThat(count).isZero();
        verify(asyncEventRepository, never()).findStalePendingEvents(any());
        verify(asyncEventRepository, never()).transitionPendingToFailed(any(), any(), any());
    }

    @Test
    void sweepStalePendingEvents_whenDisabled_doesNothingAndReturnsZero() {
        ScimAsyncEventStalePendingReaperService service = createService(false, Duration.ofMinutes(5));

        int count = service.sweepStalePendingEvents();

        assertThat(count).isZero();
        verify(asyncEventRepository, never()).findStalePendingEvents(any());
    }

    @Test
    void sweepStalePendingEvents_whenNoStaleEvents_returnsZero() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));
        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(Collections.emptyList());

        int count = service.sweepStalePendingEvents();

        assertThat(count).isZero();
        verify(asyncEventRepository).findStalePendingEvents(any());
        verify(asyncEventRepository, never()).transitionPendingToFailed(any(), any(), any());
    }

    @Test
    void sweepStalePendingEvents_whenStaleEventsFound_transitionsToFailedWithErrorSet() throws Exception {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        UUID txn1 = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        ScimAsyncEvent event1 = createPendingEvent(txn1, "POST", "User", userId);

        UUID txn2 = UUID.randomUUID();
        UUID groupId = UUID.randomUUID();
        ScimAsyncEvent event2 = createPendingEvent(txn2, "PATCH", "Group", groupId);

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event1, event2));

        String errorPayload1 = "{\"txn\":\"" + txn1 + "\",\"events\":{\"urn:ietf:params:scim:event:misc:asyncresp\":{\"status\":\"500\",\"method\":\"POST\"}}}";
        String errorPayload2 = "{\"txn\":\"" + txn2 + "\",\"events\":{\"urn:ietf:params:scim:event:misc:asyncresp\":{\"status\":\"500\",\"method\":\"PATCH\"}}}";

        when(asyncEventService.buildErrorSetPayloadSafe(eq(""), eq(txn1), eq("User"), eq(userId), eq("POST"), any()))
                .thenReturn(errorPayload1);
        when(asyncEventService.buildErrorSetPayloadSafe(eq(""), eq(txn2), eq("Group"), eq(groupId), eq("PATCH"), any()))
                .thenReturn(errorPayload2);

        when(asyncEventRepository.transitionPendingToFailed(eq(txn1), any(), eq(errorPayload1))).thenReturn(1);
        when(asyncEventRepository.transitionPendingToFailed(eq(txn2), any(), eq(errorPayload2))).thenReturn(1);

        int reapedCount = service.sweepStalePendingEvents();

        assertThat(reapedCount).isEqualTo(2);
        verify(asyncEventRepository).transitionPendingToFailed(eq(txn1), any(), eq(errorPayload1));
        verify(asyncEventRepository).transitionPendingToFailed(eq(txn2), any(), eq(errorPayload2));
    }

    @Test
    void sweepStalePendingEvents_whenTransitionFailsForOneEvent_continuesWithRemainingEvents() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        UUID txn1 = UUID.randomUUID();
        ScimAsyncEvent event1 = createPendingEvent(txn1, "POST", "User", null);

        UUID txn2 = UUID.randomUUID();
        ScimAsyncEvent event2 = createPendingEvent(txn2, "DELETE", "Group", null);

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event1, event2));

        when(asyncEventService.buildErrorSetPayloadSafe(eq(""), eq(txn1), any(), any(), eq("POST"), any()))
                .thenThrow(new RuntimeException("Simulated payload error"));

        String errorPayload2 = "{\"txn\":\"" + txn2 + "\"}";
        when(asyncEventService.buildErrorSetPayloadSafe(eq(""), eq(txn2), any(), any(), eq("DELETE"), any()))
                .thenReturn(errorPayload2);
        when(asyncEventRepository.transitionPendingToFailed(eq(txn2), any(), eq(errorPayload2))).thenReturn(1);

        int reapedCount = service.sweepStalePendingEvents();

        assertThat(reapedCount).isEqualTo(1);
        verify(asyncEventRepository).transitionPendingToFailed(eq(txn2), any(), eq(errorPayload2));
    }

    @Test
    void sweepStalePendingEvents_whenRepositoryQueryFails_handlesGracefullyAndReturnsZero() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        when(asyncEventRepository.findStalePendingEvents(any())).thenThrow(new RuntimeException("DB unavailable"));

        int reapedCount = service.sweepStalePendingEvents();

        assertThat(reapedCount).isZero();
        verify(asyncEventRepository, never()).transitionPendingToFailed(any(), any(), any());
    }

    @Test
    void sweepStalePendingEvents_withCustomTimeout_usesCustomCutoff() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        ArgumentCaptor<Instant> cutoffCaptor = ArgumentCaptor.forClass(Instant.class);
        when(asyncEventRepository.findStalePendingEvents(cutoffCaptor.capture())).thenReturn(Collections.emptyList());

        Instant before = Instant.now().minus(Duration.ofMinutes(15));
        service.sweepStalePendingEvents(Duration.ofMinutes(15));
        Instant after = Instant.now().minus(Duration.ofMinutes(15));

        Instant captured = cutoffCaptor.getValue();
        assertThat(captured).isAfterOrEqualTo(before.minusSeconds(1)).isBeforeOrEqualTo(after.plusSeconds(1));
    }

    @Test
    void sweepStalePendingEvents_realAsyncEventService_producesValidRfc9967ErrorSet() throws Exception {
        // Test with real ScimAsyncEventService to verify real RFC 9967 SET output
        ScimAsyncEventService realAsyncService = new ScimAsyncEventService(
                asyncEventRepository, null, objectMapper, (org.springframework.core.task.TaskExecutor) null);

        ScimAsyncEventStalePendingReaperService service = new ScimAsyncEventStalePendingReaperService(
                asyncEventRepository, realAsyncService, transactionOperations, true, Duration.ofMinutes(5));

        UUID txn = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        ScimAsyncEvent event = createPendingEvent(txn, "POST", "User", userId);

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event));

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        when(asyncEventRepository.transitionPendingToFailed(eq(txn), any(), payloadCaptor.capture())).thenReturn(1);

        int reaped = service.sweepStalePendingEvents();

        assertThat(reaped).isEqualTo(1);
        String payload = payloadCaptor.getValue();
        assertThat(payload).isNotEmpty();

        @SuppressWarnings("unchecked")
        Map<String, Object> setJson = objectMapper.readValue(payload, Map.class);
        assertThat(setJson.get("txn")).isEqualTo(txn.toString());
        assertThat(setJson.get("events")).isNotNull();

        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) setJson.get("events");
        @SuppressWarnings("unchecked")
        Map<String, Object> asyncResp = (Map<String, Object>) events.get("urn:ietf:params:scim:event:misc:asyncresp");
        assertThat(asyncResp).isNotNull();
        assertThat(asyncResp.get("status")).isEqualTo("500");
        assertThat(asyncResp.get("method")).isEqualTo("POST");

        @SuppressWarnings("unchecked")
        Map<String, Object> response = (Map<String, Object>) asyncResp.get("response");
        assertThat(response).isNotNull();
        assertThat(response.get("status")).isEqualTo("500");
        assertThat(response.get("detail")).isEqualTo("Asynchronous operation timed out or server restarted");
    }

    @Test
    void sweepStalePendingEvents_timingPrecision_reapsStaleEventAndLeavesFreshEvent() {
        Duration timeout = Duration.ofMinutes(5);
        // Simulate Linux JDK 25 nanosecond clock (.851123671Z) so sub-microsecond truncation is verified on all OSes
        Instant nanoNow = Instant.parse("2026-11-05T12:00:00.851123671Z");
        Instant expectedCutoff = Instant.parse("2026-11-05T11:55:00.851123Z");
        ScimAsyncEventStalePendingReaperService service = new ScimAsyncEventStalePendingReaperService(
                asyncEventRepository,
                asyncEventService,
                transactionOperations,
                Clock.fixed(nanoNow, ZoneOffset.UTC),
                true,
                timeout
        );

        UUID staleTxn = UUID.randomUUID();
        UUID freshTxn = UUID.randomUUID();
        UUID boundaryTxn = UUID.randomUUID();

        // Simulate repository query: WHERE e.status = 'PENDING' AND e.createdAt < :cutoff
        // Event created at cutoff - 1us is stale (< cutoff).
        // Event created at cutoff is not stale (not < cutoff).
        // Event created at cutoff + 1us is fresh (not < cutoff).
        when(asyncEventRepository.findStalePendingEvents(any(Instant.class))).thenAnswer(invocation -> {
            Instant queryCutoff = invocation.getArgument(0);
            assertThat(queryCutoff).isEqualTo(expectedCutoff);

            ScimAsyncEvent staleEvent = createPendingEvent(staleTxn, "POST", "User", UUID.randomUUID());
            staleEvent.setCreatedAt(queryCutoff.minus(1, ChronoUnit.MICROS));

            ScimAsyncEvent boundaryEvent = createPendingEvent(boundaryTxn, "POST", "User", UUID.randomUUID());
            boundaryEvent.setCreatedAt(queryCutoff);

            ScimAsyncEvent freshEvent = createPendingEvent(freshTxn, "POST", "User", UUID.randomUUID());
            freshEvent.setCreatedAt(queryCutoff.plus(1, ChronoUnit.MICROS));

            List<ScimAsyncEvent> candidateEvents = List.of(staleEvent, boundaryEvent, freshEvent);
            return candidateEvents.stream()
                    .filter(e -> "PENDING".equals(e.getStatus()) && e.getCreatedAt().isBefore(queryCutoff))
                    .toList();
        });

        when(asyncEventService.buildErrorSetPayloadSafe(any(), any(UUID.class), any(), any(), any(), any()))
                .thenAnswer(invocation -> "{\"txn\":\"" + invocation.getArgument(1) + "\"}");
        when(asyncEventRepository.transitionPendingToFailed(eq(staleTxn), any(), any())).thenReturn(1);

        int reaped = service.sweepStalePendingEvents(timeout);

        // Only the stale event (now - timeout - 1ms) is reaped
        assertThat(reaped).isEqualTo(1);
        verify(asyncEventRepository).transitionPendingToFailed(eq(staleTxn), any(), any());
        verify(asyncEventRepository, never()).transitionPendingToFailed(eq(freshTxn), any(), any());
        verify(asyncEventRepository, never()).transitionPendingToFailed(eq(boundaryTxn), any(), any());
    }

    @Test
    void sweepStalePendingEvents_concurrentCompletionRace_returnsZeroAndDoesNotOverwriteCompletedEvent() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        UUID racedTxn = UUID.randomUUID();
        ScimAsyncEvent event = createPendingEvent(racedTxn, "PUT", "User", UUID.randomUUID());

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event));

        String errorPayload = "{\"txn\":\"" + racedTxn + "\"}";
        when(asyncEventService.buildErrorSetPayloadSafe(any(), eq(racedTxn), any(), any(), any(), any()))
                .thenReturn(errorPayload);

        // Concurrently completed: DB row status is now COMPLETED, so transitionPendingToFailed updates 0 rows
        when(asyncEventRepository.transitionPendingToFailed(eq(racedTxn), any(), eq(errorPayload))).thenReturn(0);

        int reaped = service.sweepStalePendingEvents();

        // Must report 0 reaped since the race was won by the completing worker
        assertThat(reaped).isZero();
        verify(asyncEventRepository).transitionPendingToFailed(eq(racedTxn), any(), eq(errorPayload));
    }

    @Test
    void sweepStalePendingEvents_mixedConcurrentRace_onlyCountsSuccessfullyTransitionedEvents() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        UUID txnNormal = UUID.randomUUID();
        ScimAsyncEvent eventNormal = createPendingEvent(txnNormal, "POST", "User", UUID.randomUUID());

        UUID txnRaceWonByWorker = UUID.randomUUID();
        ScimAsyncEvent eventRaced = createPendingEvent(txnRaceWonByWorker, "DELETE", "Group", UUID.randomUUID());

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(eventNormal, eventRaced));

        when(asyncEventService.buildErrorSetPayloadSafe(any(), eq(txnNormal), any(), any(), any(), any()))
                .thenReturn("{\"txn\":\"" + txnNormal + "\"}");
        when(asyncEventService.buildErrorSetPayloadSafe(any(), eq(txnRaceWonByWorker), any(), any(), any(), any()))
                .thenReturn("{\"txn\":\"" + txnRaceWonByWorker + "\"}");

        // Event 1 is orphaned and successfully reaped
        when(asyncEventRepository.transitionPendingToFailed(eq(txnNormal), any(), any())).thenReturn(1);
        // Event 2 raced with completing worker, returning 0 rows affected
        when(asyncEventRepository.transitionPendingToFailed(eq(txnRaceWonByWorker), any(), any())).thenReturn(0);

        int reaped = service.sweepStalePendingEvents();

        assertThat(reaped).isEqualTo(1);
    }

    @Test
    void sweepStalePendingEvents_rfc9967Conformance_verifiesAllRequiredKeysAcrossAllMethods() throws Exception {
        ScimAsyncEventService realAsyncService = new ScimAsyncEventService(
                asyncEventRepository, null, objectMapper, (org.springframework.core.task.TaskExecutor) null);

        ScimAsyncEventStalePendingReaperService service = new ScimAsyncEventStalePendingReaperService(
                asyncEventRepository, realAsyncService, transactionOperations, true, Duration.ofMinutes(5));

        List<String> httpMethods = List.of("POST", "PUT", "PATCH", "DELETE");

        for (String method : httpMethods) {
            UUID txnId = UUID.randomUUID();
            UUID resourceId = UUID.randomUUID();
            ScimAsyncEvent event = createPendingEvent(txnId, method, "User", resourceId);

            when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event));

            ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
            when(asyncEventRepository.transitionPendingToFailed(eq(txnId), any(), payloadCaptor.capture())).thenReturn(1);

            int count = service.sweepStalePendingEvents();
            assertThat(count).isEqualTo(1);

            String rawPayload = payloadCaptor.getValue();
            @SuppressWarnings("unchecked")
            Map<String, Object> setJson = objectMapper.readValue(rawPayload, Map.class);

            // Top-level RFC 9967 SET fields
            assertThat(setJson).containsKey("txn");
            assertThat(setJson.get("txn")).isEqualTo(txnId.toString());
            assertThat(setJson).containsKey("iss");
            assertThat(setJson).containsKey("iat");
            assertThat(setJson).containsKey("jti");
            assertThat(setJson).containsKey("events");

            @SuppressWarnings("unchecked")
            Map<String, Object> events = (Map<String, Object>) setJson.get("events");
            assertThat(events).containsKey("urn:ietf:params:scim:event:misc:asyncresp");

            @SuppressWarnings("unchecked")
            Map<String, Object> asyncResp = (Map<String, Object>) events.get("urn:ietf:params:scim:event:misc:asyncresp");
            assertThat(asyncResp.get("status")).isEqualTo("500");
            assertThat(asyncResp.get("method")).isEqualTo(method);

            @SuppressWarnings("unchecked")
            Map<String, Object> response = (Map<String, Object>) asyncResp.get("response");
            assertThat(response).isNotNull();
            assertThat(response.get("status")).isEqualTo("500");
            assertThat(response.get("detail")).isEqualTo("Asynchronous operation timed out or server restarted");

            @SuppressWarnings("unchecked")
            List<String> schemas = (List<String>) response.get("schemas");
            assertThat(schemas).contains("urn:ietf:params:scim:api:messages:2.0:Error");

            // sub_id conformance when resource is present
            @SuppressWarnings("unchecked")
            Map<String, Object> subId = (Map<String, Object>) setJson.get("sub_id");
            assertThat(subId).isNotNull();
            assertThat(subId.get("format")).isEqualTo("uri");
            assertThat(subId.get("uri").toString()).contains("/Users/" + resourceId);
        }
    }

    @Test
    void sweepStalePendingEvents_rfc9967Conformance_whenResourceIdNull_omitsSubId() throws Exception {
        ScimAsyncEventService realAsyncService = new ScimAsyncEventService(
                asyncEventRepository, null, objectMapper, (org.springframework.core.task.TaskExecutor) null);

        ScimAsyncEventStalePendingReaperService service = new ScimAsyncEventStalePendingReaperService(
                asyncEventRepository, realAsyncService, transactionOperations, true, Duration.ofMinutes(5));

        UUID txnId = UUID.randomUUID();
        ScimAsyncEvent event = createPendingEvent(txnId, "POST", "User", null);

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(event));

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        when(asyncEventRepository.transitionPendingToFailed(eq(txnId), any(), payloadCaptor.capture())).thenReturn(1);

        int count = service.sweepStalePendingEvents();
        assertThat(count).isEqualTo(1);

        String rawPayload = payloadCaptor.getValue();
        @SuppressWarnings("unchecked")
        Map<String, Object> setJson = objectMapper.readValue(rawPayload, Map.class);
        assertThat(setJson.get("sub_id")).isNull();
    }

    @Test
    void sweepStalePendingEvents_skipsInFlightEventsOnThisNode() {
        ScimAsyncEventStalePendingReaperService service = createService(true, Duration.ofMinutes(5));

        UUID inFlightTxn = UUID.randomUUID();
        ScimAsyncEvent inFlightEvent = createPendingEvent(inFlightTxn, "POST", "User", UUID.randomUUID());

        UUID orphanedTxn = UUID.randomUUID();
        ScimAsyncEvent orphanedEvent = createPendingEvent(orphanedTxn, "POST", "User", UUID.randomUUID());

        when(asyncEventRepository.findStalePendingEvents(any())).thenReturn(List.of(inFlightEvent, orphanedEvent));
        when(asyncEventService.isInFlight(inFlightTxn)).thenReturn(true);
        when(asyncEventService.isInFlight(orphanedTxn)).thenReturn(false);

        String orphanedErrorSet = "{\"txn\":\"" + orphanedTxn + "\"}";
        when(asyncEventService.buildErrorSetPayloadSafe(any(), eq(orphanedTxn), any(), any(), any(), any()))
                .thenReturn(orphanedErrorSet);
        when(asyncEventRepository.transitionPendingToFailed(eq(orphanedTxn), any(), eq(orphanedErrorSet)))
                .thenReturn(1);

        int reaped = service.sweepStalePendingEvents();

        assertThat(reaped).isEqualTo(1);
        verify(asyncEventRepository, never()).transitionPendingToFailed(eq(inFlightTxn), any(), any());
        verify(asyncEventRepository).transitionPendingToFailed(eq(orphanedTxn), any(), eq(orphanedErrorSet));
    }
}
