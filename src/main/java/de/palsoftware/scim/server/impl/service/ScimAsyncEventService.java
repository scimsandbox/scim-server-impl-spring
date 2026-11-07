package de.palsoftware.scim.server.impl.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Service managing RFC 9967 asynchronous operations and Security Event Tokens.
 */
@Service
public class ScimAsyncEventService {

    private static final Logger log = LoggerFactory.getLogger(ScimAsyncEventService.class);

    public static final String INTERNAL_MODIFIED_ATTRIBUTES_KEY = "__scim_modified_attributes__";
    public static final String ASYNC_RESP_EVENT_URI = "urn:ietf:params:scim:event:misc:asyncresp";
    public static final int WORKER_TRANSACTION_TIMEOUT_SECONDS = 120;
    private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

    private final ScimAsyncEventRepository asyncEventRepository;
    private final WorkspaceRepository workspaceRepository;
    private final ObjectMapper objectMapper;
    private final TaskExecutor taskExecutor;
    private final ConcurrentMap<UUID, CompletableFuture<Void>> inFlightTasks = new ConcurrentHashMap<>();
    private TransactionOperations workerTransactionOperations;

    @org.springframework.beans.factory.annotation.Autowired
    public ScimAsyncEventService(ScimAsyncEventRepository asyncEventRepository,
                                 WorkspaceRepository workspaceRepository,
                                 ObjectMapper objectMapper,
                                 @Qualifier("applicationTaskExecutor") ObjectProvider<TaskExecutor> taskExecutorProvider) {
        this.asyncEventRepository = asyncEventRepository;
        this.workspaceRepository = workspaceRepository;
        this.objectMapper = objectMapper;
        this.taskExecutor = taskExecutorProvider.getIfAvailable(() -> new SimpleAsyncTaskExecutor("scim-async-"));
    }

    public ScimAsyncEventService(ScimAsyncEventRepository asyncEventRepository,
                                 WorkspaceRepository workspaceRepository,
                                 ObjectMapper objectMapper,
                                 TaskExecutor taskExecutor) {
        this.asyncEventRepository = asyncEventRepository;
        this.workspaceRepository = workspaceRepository;
        this.objectMapper = objectMapper;
        this.taskExecutor = taskExecutor != null ? taskExecutor : new SimpleAsyncTaskExecutor("scim-async-");
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager != null) {
            TransactionTemplate template = new TransactionTemplate(transactionManager);
            template.setTimeout(WORKER_TRANSACTION_TIMEOUT_SECONDS);
            this.workerTransactionOperations = template;
        }
    }

    void setWorkerTransactionOperations(TransactionOperations workerTransactionOperations) {
        this.workerTransactionOperations = workerTransactionOperations;
    }

    /**
     * Validates and normalizes async operation name to standard uppercase HTTP method:
     * "POST", "PUT", "PATCH", "DELETE". Also maps legacy "create" to "POST".
     */
    public static String canonicalizeOperation(String operation) {
        if (operation == null || operation.isBlank()) {
            throw new IllegalArgumentException("Async operation must not be null or blank");
        }
        String trimmed = operation.trim().toUpperCase(Locale.ROOT);
        return switch (trimmed) {
            case "POST", "CREATE" -> "POST";
            case "PUT" -> "PUT";
            case "PATCH" -> "PATCH";
            case "DELETE" -> "DELETE";
            default -> throw new IllegalArgumentException("Unsupported async operation: " + operation);
        };
    }

    /**
     * Persists the event in PENDING state synchronously and dispatches async background execution.
     */
    public UUID submitAsync(UUID workspaceId,
                            String operation,
                            String resourceType,
                            UUID resourceId,
                            String baseUrl,
                            Supplier<Map<String, Object>> task) {
        return submitAsync(workspaceId, operation, resourceType, resourceId, baseUrl, task, null);
    }

    @SuppressWarnings("unchecked")
    public UUID submitAsync(UUID workspaceId,
                            String operation,
                            String resourceType,
                            UUID resourceId,
                            String baseUrl,
                            Supplier<Map<String, Object>> task,
                            List<String> modifiedAttributes) {

        String canonicalOp = canonicalizeOperation(operation);
        UUID txnId = UUID.randomUUID();
        Workspace workspaceRef = workspaceRepository.getReferenceById(workspaceId);

        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(workspaceRef);
        event.setOperation(canonicalOp);
        event.setResourceType(resourceType);
        event.setResourceId(resourceId);
        event.setStatus("PENDING");
        event.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MICROS));

        // Ensure row is immediately written to the database before HTTP 202 is returned
        asyncEventRepository.saveAndFlush(event);

        CompletableFuture<Void> completion = new CompletableFuture<>();
        inFlightTasks.put(txnId, completion);
        AtomicBoolean workerStarted = new AtomicBoolean(false);

        try {
            taskExecutor.execute(() -> {
                workerStarted.set(true);
                try {
                    if (workerTransactionOperations != null) {
                        workerTransactionOperations.executeWithoutResult(status -> {
                            boolean completed = executeAndTransitionToCompleted(
                                    txnId, canonicalOp, resourceType, resourceId, baseUrl, task, modifiedAttributes);
                            if (!completed) {
                                status.setRollbackOnly();
                            }
                        });
                    } else {
                        executeAndTransitionToCompleted(
                                txnId, canonicalOp, resourceType, resourceId, baseUrl, task, modifiedAttributes);
                    }
                } catch (Throwable t) {
                    log.error("Async operation failed for txnId: {}", txnId, t);
                    try {
                        String errorSetPayload = buildErrorSetPayloadSafe(baseUrl, txnId, resourceType, resourceId, canonicalOp, t);
                        updateEventFailedWithPayload(txnId, errorSetPayload);
                    } catch (Throwable persistEx) {
                        log.error("Failed to record FAILED status for async txnId: {}", txnId, persistEx);
                    }
                    if (t instanceof Error err) {
                        throw err;
                    }
                } finally {
                    completion.complete(null);
                    inFlightTasks.remove(txnId, completion);
                }
            });
        } catch (Throwable dispatchEx) {
            if (!workerStarted.get()) {
                completion.complete(null);
                inFlightTasks.remove(txnId, completion);
                try {
                    String errorSetPayload = buildErrorSetPayloadSafe(baseUrl, txnId, resourceType, resourceId, canonicalOp, dispatchEx);
                    updateEventFailedWithPayload(txnId, errorSetPayload);
                } catch (Throwable cleanupEx) {
                    log.error("Failed to mark rejected async event {} as FAILED", txnId, cleanupEx);
                    try {
                        asyncEventRepository.deleteById(txnId);
                    } catch (Throwable ignored) {
                        // best-effort fallback cleanup
                    }
                }
            }
            if (dispatchEx instanceof RuntimeException re) {
                throw re;
            }
            if (dispatchEx instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException("Failed to dispatch async SCIM operation", dispatchEx);
        }

        return txnId;
    }

    /**
     * Waits up to {@code timeout} if the given transaction is currently executing in flight on this node,
     * eliminating immediate-GET 202 race conditions on fast local operations.
     */
    public void awaitIfInFlight(UUID txnId, Duration timeout) {
        if (txnId == null || timeout == null) {
            return;
        }
        CompletableFuture<Void> future = inFlightTasks.get(txnId);
        if (future != null) {
            try {
                future.get(Math.max(1L, timeout.toMillis()), TimeUnit.MILLISECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Exception ignored) {
                // Timed out; caller will observe current database status (e.g. PENDING -> 202)
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean executeAndTransitionToCompleted(UUID txnId,
                                                    String canonicalOp,
                                                    String resourceType,
                                                    UUID resourceId,
                                                    String baseUrl,
                                                    Supplier<Map<String, Object>> task,
                                                    List<String> modifiedAttributes) {
        Map<String, Object> rawResource = task.get();
        List<String> effectiveModifiedAttrs = modifiedAttributes;
        Map<String, Object> cleanResource = rawResource;

        if (rawResource != null && rawResource.containsKey(INTERNAL_MODIFIED_ATTRIBUTES_KEY)) {
            cleanResource = new LinkedHashMap<>(rawResource);
            Object attrObj = cleanResource.remove(INTERNAL_MODIFIED_ATTRIBUTES_KEY);
            if (effectiveModifiedAttrs == null && attrObj instanceof List<?> list) {
                effectiveModifiedAttrs = (List<String>) list;
            }
        }

        UUID effectiveResourceId = resourceId;
        if (effectiveResourceId == null && cleanResource != null && cleanResource.get("id") != null) {
            try {
                effectiveResourceId = UUID.fromString(cleanResource.get("id").toString());
            } catch (IllegalArgumentException ignored) {
                // ignore unparseable id
            }
        }

        String setPayload;
        try {
            setPayload = buildSetPayload(
                    baseUrl, txnId, canonicalOp, resourceType, effectiveResourceId, cleanResource, effectiveModifiedAttrs);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build async SET payload", e);
        }

        int updated = updateEventCompleted(txnId, effectiveResourceId, setPayload);
        if (updated == 0) {
            log.warn("Async event {} was no longer PENDING when worker finished; rolling back resource changes", txnId);
            return false;
        }
        return true;
    }

    public boolean isInFlight(UUID txnId) {
        if (txnId == null) {
            return false;
        }
        java.util.concurrent.Future<?> future = inFlightTasks.get(txnId);
        return future != null && !future.isDone();
    }

    public Optional<ScimAsyncEvent> getEvent(UUID txnId, UUID workspaceId) {
        return asyncEventRepository.findByTxnIdAndWorkspaceId(txnId, workspaceId);
    }

    @Transactional
    public int updateEventCompleted(UUID txnId, UUID resourceId, String setPayload) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        return asyncEventRepository.transitionPendingToCompleted(txnId, resourceId, now, setPayload);
    }

    public void updateEventFailed(UUID txnId, String errorMessage) {
        String op = asyncEventRepository.findById(txnId).map(ScimAsyncEvent::getOperation).orElse(null);
        String errorSet = buildErrorSetPayloadSafe("", txnId, null, null, op,
                new ScimException(500, null, errorMessage != null ? errorMessage : "Async operation failed"));
        updateEventFailedWithPayload(txnId, errorSet);
    }

    public void updateEventFailedWithPayload(UUID txnId, String errorSetPayload) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        asyncEventRepository.transitionPendingToFailed(txnId, now, errorSetPayload);
    }

    public String buildSetPayload(String baseUrl,
                                  UUID txnId,
                                  String operation,
                                  String resourceType,
                                  UUID resourceId,
                                  Map<String, Object> resource) throws Exception {
        return buildSetPayload(baseUrl, txnId, operation, resourceType, resourceId, resource, null);
    }

    /**
     * Builds the RFC 8417 / RFC 9967 Security Event Token (SET) JSON carrying both
     * {@code urn:ietf:params:scim:event:misc:asyncresp} and the corresponding provisioning event.
     */
    public String buildSetPayload(String baseUrl,
                                  UUID txnId,
                                  String operation,
                                  String resourceType,
                                  UUID resourceId,
                                  Map<String, Object> resource,
                                  List<String> modifiedAttributes) throws Exception {

        String canonicalOp = canonicalizeOperation(operation);
        Map<String, Object> sanitizedResource = sanitizeEventData(resource);

        Map<String, Object> set = new LinkedHashMap<>();
        set.put("iss", baseUrl);
        set.put("iat", Instant.now().getEpochSecond());
        set.put("jti", UUID.randomUUID().toString());
        set.put("txn", txnId.toString());

        String resourcePath = resourceType.endsWith("s") ? resourceType : resourceType + "s";
        String resourceUri = baseUrl + "/" + resourcePath + (resourceId != null ? "/" + resourceId : "");
        Map<String, Object> subId = new LinkedHashMap<>();
        subId.put("format", "uri");
        subId.put("uri", resourceUri);
        if (sanitizedResource != null && sanitizedResource.get("externalId") instanceof String ext && !ext.isBlank()) {
            subId.put("externalId", ext);
        }
        set.put("sub_id", subId);

        Map<String, Object> events = new LinkedHashMap<>();

        // 1. Asynchronous Request Completion Event (RFC 9967 §2.5.1.3)
        Map<String, Object> asyncResp = new LinkedHashMap<>();
        String httpStatus = switch (canonicalOp) {
            case "POST" -> "201";
            case "DELETE" -> "204";
            default -> "200";
        };
        asyncResp.put("status", httpStatus);
        asyncResp.put("method", canonicalOp);
        if (resourceId != null) {
            asyncResp.put("location", resourceUri);
        }
        if (!"DELETE".equals(canonicalOp) && sanitizedResource != null
                && sanitizedResource.get("meta") instanceof Map<?, ?> meta && meta.get("version") != null) {
            asyncResp.put("version", meta.get("version").toString());
        }
        events.put(ASYNC_RESP_EVENT_URI, asyncResp);

        // 2. SCIM Provisioning Event (RFC 9967 §2.4)
        switch (canonicalOp) {
            case "DELETE" -> events.put("urn:ietf:params:scim:event:prov:delete", Collections.emptyMap());
            case "PATCH" -> {
                if (modifiedAttributes != null && !modifiedAttributes.isEmpty()) {
                    events.put("urn:ietf:params:scim:event:prov:patch:notice",
                            Map.of("attributes", new ArrayList<>(modifiedAttributes)));
                } else {
                    Map<String, Object> dataObj = sanitizedResource != null && !sanitizedResource.isEmpty()
                            ? sanitizedResource
                            : (resourceId != null ? Map.of("id", resourceId.toString()) : Collections.emptyMap());
                    events.put("urn:ietf:params:scim:event:prov:patch:full", Map.of("data", dataObj));
                }
            }
            case "POST" -> {
                Map<String, Object> dataObj = sanitizedResource != null && !sanitizedResource.isEmpty()
                        ? sanitizedResource
                        : (resourceId != null ? Map.of("id", resourceId.toString()) : Collections.emptyMap());
                events.put("urn:ietf:params:scim:event:prov:create:full", Map.of("data", dataObj));
            }
            case "PUT" -> {
                Map<String, Object> dataObj = sanitizedResource != null && !sanitizedResource.isEmpty()
                        ? sanitizedResource
                        : (resourceId != null ? Map.of("id", resourceId.toString()) : Collections.emptyMap());
                events.put("urn:ietf:params:scim:event:prov:put:full", Map.of("data", dataObj));
            }
        }

        set.put("events", events);
        return objectMapper.writeValueAsString(set);
    }

    /**
     * Builds an RFC 9967 §2.5.1.3 error completion SET containing {@code misc:asyncresp} with
     * non-2xx {@code status} and RFC 7644 §3.12 {@code response}.
     */
    public String buildErrorSetPayload(String baseUrl,
                                       UUID txnId,
                                       String resourceType,
                                       UUID resourceId,
                                       String errStatus,
                                       String scimType,
                                       String detail) throws Exception {
        return buildErrorSetPayload(baseUrl, txnId, resourceType, resourceId, null, errStatus, scimType, detail);
    }

    public String buildErrorSetPayload(String baseUrl,
                                       UUID txnId,
                                       String resourceType,
                                       UUID resourceId,
                                       String operation,
                                       String errStatus,
                                       String scimType,
                                       String detail) throws Exception {
        Map<String, Object> set = new LinkedHashMap<>();
        set.put("iss", baseUrl != null ? baseUrl : "");
        set.put("iat", Instant.now().getEpochSecond());
        set.put("jti", UUID.randomUUID().toString());
        set.put("txn", txnId.toString());

        if (resourceType != null && !resourceType.isBlank() && resourceId != null) {
            String resourcePath = resourceType.endsWith("s") ? resourceType : resourceType + "s";
            String resourceUri = baseUrl + "/" + resourcePath + "/" + resourceId;
            Map<String, Object> subId = new LinkedHashMap<>();
            subId.put("format", "uri");
            subId.put("uri", resourceUri);
            set.put("sub_id", subId);
        }

        Map<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("schemas", List.of(ERROR_SCHEMA));
        errorResponse.put("status", errStatus);
        if (scimType != null && !scimType.isBlank()) {
            errorResponse.put("scimType", scimType);
        }
        errorResponse.put("detail", detail != null && !detail.isBlank() ? detail : "Asynchronous operation failed");

        Map<String, Object> asyncResp = new LinkedHashMap<>();
        asyncResp.put("status", errStatus);
        if (operation != null && !operation.isBlank()) {
            try {
                asyncResp.put("method", canonicalizeOperation(operation));
            } catch (Exception ignored) {
                asyncResp.put("method", operation.trim().toUpperCase(Locale.ROOT));
            }
        }
        asyncResp.put("response", errorResponse);

        set.put("events", Map.of(ASYNC_RESP_EVENT_URI, asyncResp));
        return objectMapper.writeValueAsString(set);
    }

    public String buildErrorSetPayloadSafe(String baseUrl, UUID txnId, String resourceType, UUID resourceId, Throwable error) {
        return buildErrorSetPayloadSafe(baseUrl, txnId, resourceType, resourceId, null, error);
    }

    public String buildErrorSetPayloadSafe(String baseUrl, UUID txnId, String resourceType, UUID resourceId, String operation, Throwable error) {
        ScimException scimEx = extractScimException(error);
        String errStatus;
        String scimType;
        String detail;

        if (scimEx != null) {
            errStatus = String.valueOf(scimEx.getHttpStatus());
            scimType = scimEx.getScimType();
            detail = scimEx.getMessage();
        } else if (hasDataIntegrityCause(error)) {
            errStatus = "409";
            scimType = "uniqueness";
            detail = "A resource with this identifier or unique attribute already exists";
        } else {
            errStatus = "500";
            scimType = null;
            detail = "Internal server error";
        }

        try {
            return buildErrorSetPayload(baseUrl, txnId, resourceType, resourceId, operation, errStatus, scimType, detail);
        } catch (Exception ex) {
            String methodField = "";
            if (operation != null && !operation.isBlank()) {
                String m = operation.trim().toUpperCase(Locale.ROOT);
                methodField = ",\"method\":\"" + m + "\"";
            }
            return "{\"txn\":\"" + txnId + "\",\"events\":{\"" + ASYNC_RESP_EVENT_URI
                    + "\":{\"status\":\"500\"" + methodField + ",\"response\":{\"schemas\":[\"" + ERROR_SCHEMA
                    + "\"],\"status\":\"500\",\"detail\":\"Internal server error\"}}}}";
        }
    }

    private static ScimException extractScimException(Throwable t) {
        Throwable curr = t;
        while (curr != null) {
            if (curr instanceof ScimException se) {
                return se;
            }
            curr = curr.getCause();
        }
        return null;
    }

    private static boolean hasDataIntegrityCause(Throwable t) {
        Throwable curr = t;
        while (curr != null) {
            if (curr instanceof DataIntegrityViolationException) {
                return true;
            }
            curr = curr.getCause();
        }
        return false;
    }

    private static Map<String, Object> sanitizeEventData(Map<String, Object> resource) {
        if (resource == null) {
            return null;
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : resource.entrySet()) {
            if ("password".equalsIgnoreCase(entry.getKey())
                    || INTERNAL_MODIFIED_ATTRIBUTES_KEY.equals(entry.getKey())) {
                continue;
            }
            copy.put(entry.getKey(), entry.getValue());
        }
        return copy;
    }
}
