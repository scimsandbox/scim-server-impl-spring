package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class WorkspaceActivityServiceTest {

    @Mock
    private WorkspaceRepository workspaceRepository;

    private static final Instant FIXED_TIME = Instant.parse("2023-01-01T10:00:00Z");
    private WorkspaceActivityService service;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(FIXED_TIME, ZoneId.of("UTC"));
        service = new WorkspaceActivityService(workspaceRepository, TransactionOperations.withoutTransaction(), clock);
    }

    @Test
    void touchWorkspace_doesNotWriteToDatabase() {
        service.touchWorkspace(UUID.randomUUID());

        verifyNoInteractions(workspaceRepository);
    }

    @Test
    void flushToDatabase_writesAllPendingUpdates() {
        UUID workspaceId1 = UUID.randomUUID();
        UUID workspaceId2 = UUID.randomUUID();

        service.touchWorkspace(workspaceId1);
        service.touchWorkspace(workspaceId2);
        service.flushToDatabase();

        verify(workspaceRepository).touchUpdatedAt(workspaceId1, FIXED_TIME);
        verify(workspaceRepository).touchUpdatedAt(workspaceId2, FIXED_TIME);
    }

    @Test
    void flushToDatabase_secondFlushWithoutNewTouches_doesNotWriteToDatabase() {
        UUID workspaceId = UUID.randomUUID();

        service.touchWorkspace(workspaceId);
        service.flushToDatabase();
        service.flushToDatabase();

        verify(workspaceRepository, times(1)).touchUpdatedAt(workspaceId, FIXED_TIME);
    }

    @Test
    void flushToDatabase_newTouchAfterFlush_isWrittenOnNextFlush() {
        UUID workspaceId = UUID.randomUUID();

        service.touchWorkspace(workspaceId);
        service.flushToDatabase();
        service.touchWorkspace(workspaceId);
        service.flushToDatabase();

        verify(workspaceRepository, times(2)).touchUpdatedAt(workspaceId, FIXED_TIME);
    }

    @Test
    void flushToDatabase_whenNoPendingUpdates_doesNotInteractWithRepository() {
        service.flushToDatabase();

        verifyNoInteractions(workspaceRepository);
    }
}

