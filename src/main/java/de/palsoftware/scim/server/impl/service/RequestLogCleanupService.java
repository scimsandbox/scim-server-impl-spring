package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
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
public class RequestLogCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(RequestLogCleanupService.class);

    public static final int DEFAULT_MAX_LOGS_TO_KEEP = 10000;

    private final ScimRequestLogRepository logRepository;
    private final WorkspaceRepository workspaceRepository;
    private final TransactionOperations transactionOperations;
    private final boolean cleanupEnabled;
    private final int maxCount;

    public RequestLogCleanupService(ScimRequestLogRepository logRepository,
                                    WorkspaceRepository workspaceRepository,
                                    TransactionOperations transactionOperations,
                                    @Value("${app.cleanup.request-logs.enabled:true}") boolean cleanupEnabled,
                                    @Value("${app.cleanup.request-logs.max-count:10000}") int maxCount) {
        this.logRepository = logRepository;
        this.workspaceRepository = workspaceRepository;
        this.transactionOperations = transactionOperations;
        this.cleanupEnabled = cleanupEnabled;
        this.maxCount = maxCount <= 0 ? DEFAULT_MAX_LOGS_TO_KEEP : maxCount;
    }

    @Scheduled(cron = "${app.cleanup.request-logs.cron:0 0 * * * *}", zone = "${app.cleanup.request-logs.zone:UTC}")
    public void deleteOldRequestLogsOnSchedule() {
        if (!cleanupEnabled) {
            return;
        }
        deleteOldRequestLogs();
    }

    public int deleteOldRequestLogs() {
        return deleteOldRequestLogs(this.maxCount);
    }

    public int deleteOldRequestLogs(int maxLogsToKeep) {
        if (!cleanupEnabled) {
            return 0;
        }

        int effectiveMaxLogs = maxLogsToKeep <= 0 ? this.maxCount : maxLogsToKeep;
        List<UUID> workspaceIds = workspaceRepository.findAllWorkspaceIds();
        int totalDeleted = 0;

        for (UUID workspaceId : workspaceIds) {
            try {
                int deleted = deleteOldRequestLogsForWorkspace(workspaceId, effectiveMaxLogs);
                if (deleted > 0) {
                    logger.debug("Deleted {} old request logs for workspace {}", deleted, workspaceId);
                    totalDeleted += deleted;
                }
            } catch (Exception e) {
                logger.error("Failed to prune request logs for workspace {}", workspaceId, e);
            }
        }

        if (totalDeleted > 0) {
            logger.info("Deleted {} old request logs across {} workspaces, retaining latest {} per workspace",
                    totalDeleted, workspaceIds.size(), effectiveMaxLogs);
        }
        return totalDeleted;
    }

    public int deleteOldRequestLogsForWorkspace(UUID workspaceId, int maxLogsToKeep) {
        int effectiveMaxLogs = maxLogsToKeep <= 0 ? this.maxCount : maxLogsToKeep;
        Integer count = transactionOperations.execute(status ->
                logRepository.deleteOldLogsByWorkspaceIdNative(workspaceId, effectiveMaxLogs));
        return count != null ? count : 0;
    }
}

