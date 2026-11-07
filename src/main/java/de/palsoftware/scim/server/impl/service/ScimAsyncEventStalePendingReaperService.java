package de.palsoftware.scim.server.impl.service;

import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
public class ScimAsyncEventStalePendingReaperService {

    private static final Logger logger = LoggerFactory.getLogger(ScimAsyncEventStalePendingReaperService.class);

    public static final Duration DEFAULT_STALE_PENDING_TIMEOUT = Duration.ofMinutes(5);
    public static final String TIMEOUT_ERROR_DETAIL = "Asynchronous operation timed out or server restarted";

    private final ScimAsyncEventRepository asyncEventRepository;
    private final ScimAsyncEventService asyncEventService;
    private final TransactionOperations transactionOperations;
    private final Clock clock;
    private final boolean reaperEnabled;
    private final Duration staleTimeout;

    @Autowired
    public ScimAsyncEventStalePendingReaperService(
            ScimAsyncEventRepository asyncEventRepository,
            ScimAsyncEventService asyncEventService,
            TransactionOperations transactionOperations,
            Clock clock,
            @Value("${app.cleanup.async-events.stale-pending.enabled:${scim.async.cleanup.stale-pending.enabled:${scim.async.stale-pending.enabled:true}}}") boolean reaperEnabled,
            @Value("${app.cleanup.async-events.stale-pending-timeout:${app.cleanup.async-events.stale-pending.timeout:${scim.async.cleanup.stale-pending-timeout:${scim.async.stale-pending-timeout:${scim.async.stale-pending.timeout:5m}}}}}") Duration staleTimeout) {
        this.asyncEventRepository = asyncEventRepository;
        this.asyncEventService = asyncEventService;
        this.transactionOperations = transactionOperations;
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.reaperEnabled = reaperEnabled;
        this.staleTimeout = (staleTimeout == null || staleTimeout.isNegative() || staleTimeout.isZero())
                ? DEFAULT_STALE_PENDING_TIMEOUT
                : staleTimeout;
    }

    @Scheduled(cron = "${app.cleanup.async-events.stale-pending.cron:${scim.async.cleanup.stale-pending.cron:${scim.async.stale-pending.cron:0 */1 * * * *}}}",
               zone = "${app.cleanup.async-events.zone:UTC}")
    public int sweepStalePendingEventsOnSchedule() {
        if (!reaperEnabled) {
            return 0;
        }
        return sweepStalePendingEvents();
    }

    public int sweepStalePendingEvents() {
        return sweepStalePendingEvents(this.staleTimeout);
    }

    public int sweepStalePendingEvents(Duration timeout) {
        if (!reaperEnabled) {
            return 0;
        }

        Duration effectiveTimeout = (timeout == null || timeout.isNegative() || timeout.isZero())
                ? this.staleTimeout
                : timeout;
        Instant cutoff = Instant.now(clock).minus(effectiveTimeout).truncatedTo(ChronoUnit.MICROS);

        List<ScimAsyncEvent> staleEvents;
        try {
            staleEvents = asyncEventRepository.findStalePendingEvents(cutoff);
        } catch (Exception e) {
            logger.error("Failed to query stale pending async events", e);
            return 0;
        }

        if (staleEvents == null || staleEvents.isEmpty()) {
            return 0;
        }

        int reapedCount = 0;
        for (ScimAsyncEvent event : staleEvents) {
            if (asyncEventService.isInFlight(event.getTxnId())) {
                continue;
            }
            try {
                String errorSet = asyncEventService.buildErrorSetPayloadSafe(
                        "",
                        event.getTxnId(),
                        event.getResourceType(),
                        event.getResourceId(),
                        event.getOperation(),
                        new ScimException(500, null, TIMEOUT_ERROR_DETAIL)
                );

                Instant completedAt = Instant.now(clock).truncatedTo(ChronoUnit.MICROS);
                Integer updated = transactionOperations.execute(status ->
                        asyncEventRepository.transitionPendingToFailed(
                                event.getTxnId(),
                                completedAt,
                                errorSet
                        )
                );

                if (updated != null && updated > 0) {
                    reapedCount++;
                    logger.warn("Reaped orphaned PENDING async event {} (operation={}, resourceType={}, createdAt={})",
                            event.getTxnId(), event.getOperation(), event.getResourceType(), event.getCreatedAt());
                }
            } catch (Exception e) {
                logger.error("Failed to reap stale pending async event {}", event.getTxnId(), e);
            }
        }

        if (reapedCount > 0) {
            logger.info("Successfully reaped {} stale PENDING async events older than {}", reapedCount, effectiveTimeout);
        }

        return reapedCount;
    }
}
