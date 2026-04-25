package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.UUID;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class WorkspaceActivityServiceTest {

    @Mock
    private WorkspaceRepository workspaceRepository;

    private Clock clock;
    private WorkspaceActivityService service;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.parse("2023-01-01T10:00:00Z"), ZoneId.of("UTC"));
        service = new WorkspaceActivityService(workspaceRepository, clock);
    }

    @Test
    void touchWorkspace_callsRepositoryWithCurrentTime() {
        // Arrange
        UUID workspaceId = UUID.randomUUID();

        // Act
        service.touchWorkspace(workspaceId);

        // Assert
        verify(workspaceRepository).touchUpdatedAt(workspaceId, Instant.now(clock));
    }
}
