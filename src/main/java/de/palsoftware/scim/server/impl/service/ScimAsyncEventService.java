package de.palsoftware.scim.server.impl.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

/**
 * Service managing RFC 9967 asynchronous operations and Security Event Tokens.
 */
@Service
public class ScimAsyncEventService {

    private static final Logger log = LoggerFactory.getLogger(ScimAsyncEventService.class);

    private final ScimAsyncEventRepository asyncEventRepository;
    private final WorkspaceRepository workspaceRepository;
    private final ObjectMapper objectMapper;
    private final TaskExecutor taskExecutor;

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

    /**
     * Persists the event in PENDING state synchronously and dispatches async background execution.
     *
     * @param workspaceId  the workspace ID
     * @param operation    the SCIM operation (create, put, patch, delete)
     * @param resourceType the target resource type (User, Group)
     * @param resourceId   the target resource ID if known beforehand (may be null for create)
     * @param baseUrl      the base URL for constructing SET claims and Location
     * @param task         the synchronous mutation task to execute asynchronously
     * @return the generated transaction UUID
     */
    public UUID submitAsync(UUID workspaceId,
                            String operation,
                            String resourceType,
                            UUID resourceId,
                            String baseUrl,
                            Supplier<Map<String, Object>> task) {

        UUID txnId = UUID.randomUUID();
        Workspace workspaceRef = workspaceRepository.getReferenceById(workspaceId);

        ScimAsyncEvent event = new ScimAsyncEvent();
        event.setTxnId(txnId);
        event.setWorkspace(workspaceRef);
        event.setOperation(operation.toLowerCase(Locale.ROOT));
        event.setResourceType(resourceType);
        event.setResourceId(resourceId);
        event.setStatus("PENDING");
        event.setCreatedAt(Instant.now());

        // Ensure row is immediately written to the database before HTTP 202 is returned
        asyncEventRepository.saveAndFlush(event);

        // Dispatch background execution
        taskExecutor.execute(() -> {
            try {
                Map<String, Object> resource = task.get();
                UUID effectiveResourceId = resourceId;
                if (effectiveResourceId == null && resource != null && resource.get("id") != null) {
                    try {
                        effectiveResourceId = UUID.fromString(resource.get("id").toString());
                    } catch (IllegalArgumentException ignored) {
                        // ignore unparseable id
                    }
                }

                String setPayload = buildSetPayload(baseUrl, txnId, operation, resourceType, effectiveResourceId, resource);
                updateEventCompleted(txnId, effectiveResourceId, setPayload);
            } catch (Exception e) {
                log.error("Async operation failed for txnId: {}", txnId, e);
                updateEventFailed(txnId, e.getMessage());
            }
        });

        return txnId;
    }

    public Optional<ScimAsyncEvent> getEvent(UUID txnId, UUID workspaceId) {
        return asyncEventRepository.findByTxnIdAndWorkspaceId(txnId, workspaceId);
    }

    @Transactional
    public void updateEventCompleted(UUID txnId, UUID resourceId, String setPayload) {
        asyncEventRepository.findById(txnId).ifPresent(event -> {
            event.setStatus("COMPLETED");
            if (resourceId != null) {
                event.setResourceId(resourceId);
            }
            event.setSetPayload(setPayload);
            event.setCompletedAt(Instant.now());
            asyncEventRepository.save(event);
        });
    }

    @Transactional
    public void updateEventFailed(UUID txnId, String errorMessage) {
        asyncEventRepository.findById(txnId).ifPresent(event -> {
            event.setStatus("FAILED");
            event.setCompletedAt(Instant.now());
            try {
                Map<String, Object> errorPayload = Map.of(
                        "schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"),
                        "status", "500",
                        "detail", errorMessage != null ? errorMessage : "Async operation failed"
                );
                event.setSetPayload(objectMapper.writeValueAsString(errorPayload));
            } catch (Exception ex) {
                event.setSetPayload("{\"status\":\"500\",\"detail\":\"Internal Error\"}");
            }
            asyncEventRepository.save(event);
        });
    }

    /**
     * Builds the RFC 8417 / RFC 9967 Security Event Token (SET) JSON.
     */
    public String buildSetPayload(String baseUrl,
                                  UUID txnId,
                                  String operation,
                                  String resourceType,
                                  UUID resourceId,
                                  Map<String, Object> resource) throws Exception {

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
        set.put("sub_id", subId);

        String eventKey = "urn:ietf:params:scim:event:prov:" + operation.toLowerCase(Locale.ROOT) + ":full";
        Map<String, Object> eventData;
        if (resource != null && !resource.isEmpty()) {
            eventData = resource;
        } else if (resourceId != null) {
            eventData = Map.of("id", resourceId.toString());
        } else {
            eventData = Collections.emptyMap();
        }
        set.put("events", Map.of(eventKey, eventData));

        return objectMapper.writeValueAsString(set);
    }
}
