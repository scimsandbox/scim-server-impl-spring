package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class WorkspaceActivityService {

    private final WorkspaceRepository workspaceRepository;
    private final Clock clock;

    public WorkspaceActivityService(WorkspaceRepository workspaceRepository, Clock clock) {
        this.workspaceRepository = workspaceRepository;
        this.clock = clock;
    }

    @Transactional
    public void touchWorkspace(UUID workspaceId) {
        workspaceRepository.touchUpdatedAt(workspaceId, Instant.now(clock));
    }
}