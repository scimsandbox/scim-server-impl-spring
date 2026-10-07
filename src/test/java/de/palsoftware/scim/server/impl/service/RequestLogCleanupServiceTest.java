package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
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
class RequestLogCleanupServiceTest {

    @Mock
    private ScimRequestLogRepository logRepository;

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

    private RequestLogCleanupService createService(boolean enabled, int maxCount) {
        return new RequestLogCleanupService(logRepository, workspaceRepository, transactionOperations, enabled, maxCount);
    }

    @Test
    void deleteOldRequestLogsOnSchedule_whenDisabled_doesNothing() {
        RequestLogCleanupService service = createService(false, 10000);

        service.deleteOldRequestLogsOnSchedule();

        verify(workspaceRepository, never()).findAllWorkspaceIds();
        verify(logRepository, never()).deleteOldLogsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldRequestLogs_whenDisabled_doesNothingAndReturnsZero() {
        RequestLogCleanupService service = createService(false, 10000);

        int deleted = service.deleteOldRequestLogs();

        assertThat(deleted).isZero();
        verify(workspaceRepository, never()).findAllWorkspaceIds();
        verify(logRepository, never()).deleteOldLogsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldRequestLogsForWorkspace_whenDisabled_doesNothingAndReturnsZero() {
        RequestLogCleanupService service = createService(false, 10000);
        UUID wsId = UUID.randomUUID();

        int deleted = service.deleteOldRequestLogsForWorkspace(wsId, 10000);

        assertThat(deleted).isZero();
        verify(logRepository, never()).deleteOldLogsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldRequestLogsOnSchedule_whenEnabled_executesPruning() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID wsId = UUID.randomUUID();
        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000)).thenReturn(25);

        service.deleteOldRequestLogsOnSchedule();

        verify(workspaceRepository).findAllWorkspaceIds();
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000);
    }

    @Test
    void deleteOldRequestLogs_multipleWorkspaces_prunesEachWorkspaceIndependently() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();
        UUID ws3 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2, ws3));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000)).thenReturn(50);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000)).thenReturn(0);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws3, 10000, 5000)).thenReturn(12);

        int totalDeleted = service.deleteOldRequestLogs();

        assertThat(totalDeleted).isEqualTo(62);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws3, 10000, 5000);
    }

    @Test
    void deleteOldRequestLogs_whenUnderThreshold_returnsZero() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000)).thenReturn(0);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000)).thenReturn(0);

        int totalDeleted = service.deleteOldRequestLogs();

        assertThat(totalDeleted).isZero();
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000);
    }

    @Test
    void deleteOldRequestLogs_whenOneWorkspaceThrowsException_continuesWithRemainingWorkspaces() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID ws1 = UUID.randomUUID();
        UUID ws2 = UUID.randomUUID();
        UUID ws3 = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(ws1, ws2, ws3));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000)).thenReturn(10);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000)).thenThrow(new RuntimeException("Simulated DB timeout"));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(ws3, 10000, 5000)).thenReturn(5);

        int totalDeleted = service.deleteOldRequestLogs();

        // ws1 (10) + ws3 (5) = 15; ws2 failure was contained
        assertThat(totalDeleted).isEqualTo(15);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws1, 10000, 5000);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws2, 10000, 5000);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(ws3, 10000, 5000);
    }

    @Test
    void deleteOldRequestLogs_customMaxCount_passesSpecifiedLimit() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID wsId = UUID.randomUUID();

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(List.of(wsId));
        when(logRepository.deleteOldLogsByWorkspaceIdNative(wsId, 500, 5000)).thenReturn(42);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000)).thenReturn(10);

        int totalDeleted = service.deleteOldRequestLogs(500);

        assertThat(totalDeleted).isEqualTo(42);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(wsId, 500, 5000);

        // When maxLogsToKeep <= 0, defaults to configured maxCount (10000)
        int nonPositiveDeleted = service.deleteOldRequestLogs(0);
        assertThat(nonPositiveDeleted).isEqualTo(10);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000);
    }

    @Test
    void deleteOldRequestLogs_whenNoWorkspaces_returnsZero() {
        RequestLogCleanupService service = createService(true, 10000);

        when(workspaceRepository.findAllWorkspaceIds()).thenReturn(Collections.emptyList());

        int totalDeleted = service.deleteOldRequestLogs();

        assertThat(totalDeleted).isZero();
        verify(logRepository, never()).deleteOldLogsByWorkspaceIdNative(any(), anyInt(), anyInt());
    }

    @Test
    void deleteOldRequestLogsForWorkspace_prunesSpecifiedWorkspace() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID wsId = UUID.randomUUID();

        when(logRepository.deleteOldLogsByWorkspaceIdNative(wsId, 2000, 5000)).thenReturn(15);
        when(logRepository.deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000)).thenReturn(5);

        int deleted = service.deleteOldRequestLogsForWorkspace(wsId, 2000);

        assertThat(deleted).isEqualTo(15);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(wsId, 2000, 5000);

        // When maxLogsToKeep <= 0, defaults to configured maxCount (10000)
        int defaultDeleted = service.deleteOldRequestLogsForWorkspace(wsId, -1);
        assertThat(defaultDeleted).isEqualTo(5);
        verify(logRepository).deleteOldLogsByWorkspaceIdNative(wsId, 10000, 5000);

        // If service was initialized with non-positive maxCount, constructor defaults to DEFAULT_MAX_LOGS_TO_KEEP (10000)
        RequestLogCleanupService defaultService = createService(true, -50);
        int negativeConfigDeleted = defaultService.deleteOldRequestLogsForWorkspace(wsId, 0);
        assertThat(negativeConfigDeleted).isEqualTo(5);
    }

    @Test
    void deleteOldRequestLogsForWorkspace_multiBatch_loopsUntilBatchExhausted() {
        RequestLogCleanupService service = createService(true, 10000);
        UUID wsId = UUID.randomUUID();

        // Custom batchSize of 100:
        // Batch 1 returns 100 (full batch, continue)
        // Batch 2 returns 100 (full batch, continue)
        // Batch 3 returns 45 (< 100, terminates)
        when(logRepository.deleteOldLogsByWorkspaceIdNative(eq(wsId), eq(1000), eq(100)))
                .thenReturn(100)
                .thenReturn(100)
                .thenReturn(45);

        int totalDeleted = service.deleteOldRequestLogsForWorkspace(wsId, 1000, 100);

        assertThat(totalDeleted).isEqualTo(245);
        verify(logRepository, times(3)).deleteOldLogsByWorkspaceIdNative(wsId, 1000, 100);
    }
}
