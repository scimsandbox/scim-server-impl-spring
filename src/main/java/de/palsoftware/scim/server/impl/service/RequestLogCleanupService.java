package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionOperations;

@Service
public class RequestLogCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(RequestLogCleanupService.class);

    private final ScimRequestLogRepository logRepository;
    private final TransactionOperations transactionOperations;
    private final boolean cleanupEnabled;
    private final int maxCount;

    public RequestLogCleanupService(ScimRequestLogRepository logRepository,
                                    TransactionOperations transactionOperations,
                                    @Value("${app.cleanup.request-logs.enabled}") boolean cleanupEnabled,
                                    @Value("${app.cleanup.request-logs.max-count}") int maxCount) {
        this.logRepository = logRepository;
        this.transactionOperations = transactionOperations;
        this.cleanupEnabled = cleanupEnabled;
        this.maxCount = maxCount;
    }

    @Scheduled(cron = "${app.cleanup.request-logs.cron:0 0 * * * *}", zone = "${app.cleanup.request-logs.zone:UTC}")
    public void deleteOldRequestLogsOnSchedule() {
        if (!cleanupEnabled) {
            return;
        }
        Integer deletedCount = transactionOperations.execute(status -> logRepository.deleteOldLogsNative(maxCount));
        if (deletedCount != null && deletedCount > 0) {
            logger.info("Deleted {} old request logs, keeping the latest {}", deletedCount, maxCount);
        }
    }
}
