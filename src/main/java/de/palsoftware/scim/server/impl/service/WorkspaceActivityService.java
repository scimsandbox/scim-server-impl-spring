package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WorkspaceActivityService {

    private static final Logger logger = LoggerFactory.getLogger(WorkspaceActivityService.class);

    private final WorkspaceRepository workspaceRepository;
    private final TransactionOperations transactionOperations;
    private final Clock clock;
    private final ConcurrentHashMap<UUID, Instant> pendingUpdates = new ConcurrentHashMap<>();

    public WorkspaceActivityService(
            WorkspaceRepository workspaceRepository,
            TransactionOperations transactionOperations,
            Clock clock) {
        this.workspaceRepository = workspaceRepository;
        this.transactionOperations = transactionOperations;
        this.clock = clock;
    }

    public void touchWorkspace(UUID workspaceId) {
        pendingUpdates.put(workspaceId, Instant.now(clock));
    }

    @Scheduled(cron = "${app.workspace.activity.flush-cron:0 0 * * * *}")
    public void flushToDatabase() {
        if (pendingUpdates.isEmpty()) {
            return;
        }
        int count = 0;
        for (Map.Entry<UUID, Instant> entry : pendingUpdates.entrySet()) {
            UUID workspaceId = entry.getKey();
            Instant updatedAt = entry.getValue();
            transactionOperations.executeWithoutResult(status ->
                workspaceRepository.touchUpdatedAt(workspaceId, updatedAt));
            // Conditional remove: if a newer touch arrived between read and here, it stays for next flush
            pendingUpdates.remove(workspaceId, updatedAt);
            count++;
        }
        logger.info("Flushed {} workspace activity updates to database", count);
    }
}