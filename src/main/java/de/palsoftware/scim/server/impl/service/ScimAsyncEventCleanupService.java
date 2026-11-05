package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionOperations;

import java.util.List;
import java.util.UUID;

@Service
public class ScimAsyncEventCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(ScimAsyncEventCleanupService.class);

    public static final int DEFAULT_MAX_EVENTS_TO_KEEP = 5000;
    public static final int DEFAULT_PRUNE_BATCH_SIZE = 5000;

    private final ScimAsyncEventRepository asyncEventRepository;
    private final WorkspaceRepository workspaceRepository;
    private final TransactionOperations transactionOperations;
    private final boolean cleanupEnabled;
    private final int maxCount;

    public ScimAsyncEventCleanupService(
            ScimAsyncEventRepository asyncEventRepository,
            WorkspaceRepository workspaceRepository,
            TransactionOperations transactionOperations,
            @Value("${app.cleanup.async-events.enabled:${scim.async.cleanup.enabled:true}}") boolean cleanupEnabled,
            @Value("${app.cleanup.async-events.max-count:${scim.async.cleanup.max-count:5000}}") int maxCount) {
        this.asyncEventRepository = asyncEventRepository;
        this.workspaceRepository = workspaceRepository;
        this.transactionOperations = transactionOperations;
        this.cleanupEnabled = cleanupEnabled;
        this.maxCount = maxCount <= 0 ? DEFAULT_MAX_EVENTS_TO_KEEP : maxCount;
    }

    @Scheduled(cron = "${app.cleanup.async-events.cron:${scim.async.cleanup.cron:0 0 * * * *}}",
               zone = "${app.cleanup.async-events.zone:UTC}")
    public void deleteOldTerminalEventsOnSchedule() {
        if (!cleanupEnabled) {
            return;
        }
        deleteOldTerminalEvents();
    }

    public int deleteOldTerminalEvents() {
        return deleteOldTerminalEvents(this.maxCount);
    }

    public int deleteOldTerminalEvents(int maxEventsToKeep) {
        if (!cleanupEnabled) {
            return 0;
        }

        int effectiveMaxEvents = maxEventsToKeep <= 0 ? this.maxCount : maxEventsToKeep;
        List<UUID> workspaceIds = workspaceRepository.findAllWorkspaceIds();
        int totalDeleted = 0;
        int prunedWorkspaces = 0;

        for (UUID workspaceId : workspaceIds) {
            try {
                int deleted = deleteOldTerminalEventsForWorkspace(workspaceId, effectiveMaxEvents);
                if (deleted > 0) {
                    logger.debug("Deleted {} old terminal async events for workspace {}", deleted, workspaceId);
                    totalDeleted += deleted;
                    prunedWorkspaces++;
                }
            } catch (Exception e) {
                logger.error("Failed to prune terminal async events for workspace {}", workspaceId, e);
            }
        }

        if (totalDeleted > 0) {
            logger.info("Deleted {} old terminal async events across {} workspaces, retaining latest {} per workspace",
                    totalDeleted, prunedWorkspaces, effectiveMaxEvents);
        }
        return totalDeleted;
    }

    public int deleteOldTerminalEventsForWorkspace(UUID workspaceId, int maxEventsToKeep) {
        return deleteOldTerminalEventsForWorkspace(workspaceId, maxEventsToKeep, DEFAULT_PRUNE_BATCH_SIZE);
    }

    public int deleteOldTerminalEventsForWorkspace(UUID workspaceId, int maxEventsToKeep, int batchSize) {
        if (!cleanupEnabled) {
            return 0;
        }
        int effectiveMaxEvents = maxEventsToKeep <= 0 ? this.maxCount : maxEventsToKeep;
        int effectiveBatchSize = batchSize <= 0 ? DEFAULT_PRUNE_BATCH_SIZE : batchSize;
        int totalDeleted = 0;

        while (true) {
            Integer count = transactionOperations.execute(status ->
                    asyncEventRepository.deleteOldTerminalEventsByWorkspaceIdNative(workspaceId, effectiveMaxEvents, effectiveBatchSize));
            int deleted = count != null ? count : 0;
            totalDeleted += deleted;
            if (deleted < effectiveBatchSize) {
                break;
            }
        }
        return totalDeleted;
    }
}
