package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionOperations;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimAsyncEventCleanupServiceTest {

    @Mock
    private ScimAsyncEventRepository asyncEventRepository;

    @Mock
    private WorkspaceRepository workspaceRepository;

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

    private ScimAsyncEventCleanupService createService(boolean enabled, int maxCount) {
        return new ScimAsyncEventCleanupService(asyncEventRepository, workspaceRepository, transactionOperations, enabled, maxCount);
    }

    @Test
    void deleteOldTerminalEventsOnSchedule_whenDisabled_doesNothing() {
        ScimAsyncEventCleanupService service = createService(false, 5000);

        service.deleteOldTerminalEventsOnSchedule();

        verify(workspaceRepository, never()).findAllWorkspaceIds();
        verify(asyncEventRepository, never()).deleteOldTerminalEventsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldTerminalEvents_whenDisabled_doesNothingAndReturnsZero() {
        ScimAsyncEventCleanupService service = createService(false, 5000);

        int deleted = service.deleteOldTerminalEvents();

        assertThat(deleted).isZero();
        verify(workspaceRepository, never()).findAllWorkspaceIds();
        verify(asyncEventRepository, never()).deleteOldTerminalEventsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldTerminalEventsForWorkspace_whenDisabled_doesNothingAndReturnsZero() {
        ScimAsyncEventCleanupService service = createService(false, 5000);
        UUID wsId = UUID.randomUUID();

        int deleted = service.deleteOldTerminalEventsForWorkspace(wsId, 5000);

        assertThat(deleted).isZero();
        verify(asyncEventRepository, never()).deleteOldTerminalEventsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldTerminalEventsOnSchedule_whenEnabled_executesPruning() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000)).thenReturn(25);

        service.deleteOldTerminalEventsOnSchedule();

        verify(workspaceRepository).findAllWorkspaceIds();
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_multipleWorkspaces_prunesEachWorkspaceIndependently() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();
        UUID ws3 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2, ws3));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000)).thenReturn(50);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000)).thenReturn(0);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws3, 5000, 5000)).thenReturn(12);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isEqualTo(62);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws3, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_whenUnderThreshold_returnsZero() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000)).thenReturn(0);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000)).thenReturn(0);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isZero();
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_whenOneWorkspaceThrowsException_continuesWithRemainingWorkspaces() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();
        UUID ws3 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2, ws3));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000)).thenReturn(10);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000)).thenThrow(new RuntimeException("Simulated DB timeout"));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(ws3, 5000, 5000)).thenReturn(5);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isEqualTo(15);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws1, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws2, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(ws3, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_customMaxCount_passesSpecifiedLimit() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 500, 5000)).thenReturn(42);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000)).thenReturn(10);

        int totalDeleted = service.deleteOldTerminalEvents(500);

        assertThat(totalDeleted).isEqualTo(42);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 500, 5000);

        int nonPositiveDeleted = service.deleteOldTerminalEvents(0);
        assertThat(nonPositiveDeleted).isEqualTo(10);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_whenNoWorkspaces_returnsZero() {
        ScimAsyncEventCleanupService service = createService(true, 5000);

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(Collections.emptyList());

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isZero();
        verify(asyncEventRepository, never()).deleteOldTerminalEventsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldTerminalEventsForWorkspace_prunesSpecifiedWorkspace() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();

        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 2000, 5000)).thenReturn(15);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000)).thenReturn(5);

        int deleted = service.deleteOldTerminalEventsForWorkspace(wsId, 2000);

        assertThat(deleted).isEqualTo(15);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 2000, 5000);

        int defaultDeleted = service.deleteOldTerminalEventsForWorkspace(wsId, -1);
        assertThat(defaultDeleted).isEqualTo(5);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000);

        ScimAsyncEventCleanupService defaultService = createService(true, -50);
        int negativeConfigDeleted = defaultService.deleteOldTerminalEventsForWorkspace(wsId, 0);
        assertThat(negativeConfigDeleted).isEqualTo(5);
    }

    @Test
    void deleteOldTerminalEventsForWorkspace_multiBatch_loopsUntilBatchExhausted() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();

        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(eq(wsId), eq(1000), eq(100)))
                .thenReturn(100)
                .thenReturn(100)
                .thenReturn(45);

        int totalDeleted = service.deleteOldTerminalEventsForWorkspace(wsId, 1000, 100);

        assertThat(totalDeleted).isEqualTo(245);
        verify(asyncEventRepository, times(3)).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 1000, 100);
    }

    @Test
    void deleteOldTerminalEvents_workspaceWithZeroEvents_returnsZero() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000)).thenReturn(0);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isZero();
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000);
    }

    @Test
    void deleteOldTerminalEvents_workspaceWithMaxCountOrFewerEvents_returnsZero() {
        int maxCount = 100;
        ScimAsyncEventCleanupService service = createService(true, maxCount);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, maxCount, 5000)).thenReturn(0);

        int totalDeleted = service.deleteOldTerminalEvents(maxCount);

        assertThat(totalDeleted).isZero();
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(wsId, maxCount, 5000);
    }

    @Test
    void deleteOldTerminalEvents_workspaceWithMaxCountPlusOneEvents_deletesExactlyOneEvent() {
        int maxCount = 5000;
        ScimAsyncEventCleanupService service = createService(true, maxCount);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, maxCount, 5000)).thenReturn(1);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isEqualTo(1);
        verify(asyncEventRepository, times(1)).deleteOldTerminalEventsByWorkspaceIdNative(wsId, maxCount, 5000);
    }

    @Test
    void deleteOldTerminalEvents_pendingEventsAreNeverPruned_contractAndBehavior() throws NoSuchMethodException {
        // 1. Verify repository annotation contract: delete query MUST restrict status IN ('COMPLETED', 'FAILED')
        java.lang.reflect.Method method = ScimAsyncEventRepository.class.getMethod(
                "deleteOldTerminalEventsByWorkspaceIdNative", UUID.class, int.class, int.class);
        org.springframework.data.jpa.repository.Query queryAnnotation =
                method.getAnnotation(org.springframework.data.jpa.repository.Query.class);
        assertThat(queryAnnotation).isNotNull();
        String sql = queryAnnotation.value().toUpperCase();
        assertThat(sql).contains("STATUS IN ('COMPLETED', 'FAILED')");
        assertThat(sql).doesNotContain("'PENDING'");

        // 2. Service level verification: terminal cleanup delegates exclusively to deleteOldTerminalEventsByWorkspaceIdNative
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(wsId, 5000, 5000)).thenReturn(0);

        int deleted = service.deleteOldTerminalEvents();
        assertThat(deleted).isZero();
        verify(asyncEventRepository, never()).deleteAllByWorkspaceId(any());
        verify(asyncEventRepository, never()).delete(any());
    }

    @Test
    void deleteOldTerminalEvents_multiTenantWorkspaceIsolation_pruningWorkspaceADoesNotTouchWorkspaceB() {
        ScimAsyncEventCleanupService service = createService(true, 5000);
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(tenantA, tenantB));
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(tenantA, 5000, 5000)).thenReturn(100);
        when(asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(tenantB, 5000, 5000)).thenReturn(0);

        int totalDeleted = service.deleteOldTerminalEvents();

        assertThat(totalDeleted).isEqualTo(100);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(tenantA, 5000, 5000);
        verify(asyncEventRepository).deleteOldTerminalEventsByWorkspaceIdNative(tenantB, 5000, 5000);
    }
}
