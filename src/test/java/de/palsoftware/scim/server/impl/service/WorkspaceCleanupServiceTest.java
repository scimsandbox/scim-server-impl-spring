package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WorkspaceCleanupServiceTest {

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
    private Clock clock;

    private WorkspaceCleanupService createService(boolean enabled, String staleAfter) {
        clock = Clock.fixed(Instant.parse("2023-04-01T10:00:00Z"), ZoneId.of("UTC"));
        return new WorkspaceCleanupService(workspaceRepository, transactionOperations, clock, enabled, staleAfter);
    }

    @Test
    void deleteStaleWorkspacesOnSchedule_whenDisabled_doesNothing() {
        // Arrange
        WorkspaceCleanupService service = createService(false, "P3M");

        // Act
        service.deleteStaleWorkspacesOnSchedule();

        // Assert
        verify(workspaceRepository, never()).deleteByUpdatedAtBefore(any());
    }

    @Test
    void deleteStaleWorkspacesOnSchedule_whenEnabled_deletesExpectedWorkspaces() {
        // Arrange
        WorkspaceCleanupService service = createService(true, "P3M"); // 3 months
        when(workspaceRepository.deleteByUpdatedAtBefore(any())).thenReturn(5);

        // Act
        service.deleteStaleWorkspacesOnSchedule();

        // Assert
        ArgumentCaptor<Instant> captor = ArgumentCaptor.forClass(Instant.class);
        verify(workspaceRepository).deleteByUpdatedAtBefore(captor.capture());
        
        // 2023-04-01 minus 3 months -> 2023-01-01
        Instant expectedCutoff = Instant.parse("2023-01-01T10:00:00Z");
        assertThat(captor.getValue()).isEqualTo(expectedCutoff);
    }

    @Test
    void deleteStaleWorkspaces_manualCall_usesProvidedInstant() {
        // Arrange
        WorkspaceCleanupService service = createService(true, "P1D"); // 1 day
        when(workspaceRepository.deleteByUpdatedAtBefore(any())).thenReturn(2);
        
        Instant manualTime = Instant.parse("2023-05-02T12:00:00Z");

        // Act
        int deleted = service.deleteStaleWorkspaces(manualTime);

        // Assert
        assertThat(deleted).isEqualTo(2);

        ArgumentCaptor<Instant> captor = ArgumentCaptor.forClass(Instant.class);
        verify(workspaceRepository).deleteByUpdatedAtBefore(captor.capture());
        
        // manualTime minus 1 day -> 2023-05-01
        Instant expectedCutoff = Instant.parse("2023-05-01T12:00:00Z");
        assertThat(captor.getValue()).isEqualTo(expectedCutoff);
    }
}
