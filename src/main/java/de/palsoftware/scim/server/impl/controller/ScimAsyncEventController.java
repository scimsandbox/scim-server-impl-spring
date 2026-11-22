package de.palsoftware.scim.server.impl.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import de.palsoftware.scim.server.impl.service.ScimAsyncEventService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * SCIM 2.0 Asynchronous Operations polling endpoint per RFC 9967 §2.5.1.1 & §3.
 * Handles GET /Events/{txnId}.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Events", "/ws/{workspaceId}/scim/v2/{compat}/Events"})
public class ScimAsyncEventController extends ScimBaseController {

    private static final String RESOURCE_EVENT = "Event";
    private static final Duration IN_FLIGHT_AWAIT_TIMEOUT = Duration.ofSeconds(2);
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

    private final ScimAsyncEventRepository asyncEventRepository;
    private final ObjectMapper objectMapper;
    private final ScimAsyncEventService asyncEventService;

    public ScimAsyncEventController(ScimAsyncEventRepository asyncEventRepository,
                                    ObjectMapper objectMapper,
                                    ScimAsyncEventService asyncEventService) {
        this.asyncEventRepository = asyncEventRepository;
        this.objectMapper = objectMapper;
        this.asyncEventService = asyncEventService;
    }

    /**
     * Polls the status of an asynchronous operation transaction.
     *
     * @param workspaceId the workspace identifier
     * @param txnId       the transaction UUID
     * @param compat      optional compatibility segment (e.g. "ms")
     * @param request     the HTTP servlet request
     * @return 202 Accepted if PENDING, 200 OK with SET JSON if COMPLETED or FAILED with SET payload, 404 if not found
     */
    @GetMapping("/{txnId}")
    public ResponseEntity<?> getEvent(
            @PathVariable String workspaceId,
            @PathVariable String txnId,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        UUID transactionId = parseUUID(txnId, RESOURCE_EVENT);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        ScimAsyncEvent event = asyncEventRepository.findByTxnIdAndWorkspaceId(transactionId, wsId)
                .orElseThrow(() -> new ScimException(404, null, "Async event not found: " + txnId));

        if ("PENDING".equalsIgnoreCase(event.getStatus())) {
            asyncEventService.awaitIfInFlight(transactionId, IN_FLIGHT_AWAIT_TIMEOUT);
            event = asyncEventRepository.findByTxnIdAndWorkspaceId(transactionId, wsId)
                    .orElse(event);
        }

        if ("PENDING".equalsIgnoreCase(event.getStatus())) {
            String location = baseUrl + "/Events/" + transactionId;
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .header(ScimPreferHeaderUtil.SET_TXN_HEADER, transactionId.toString())
                    .header("Location", location)
                    .build();
        }

        if ("COMPLETED".equalsIgnoreCase(event.getStatus())) {
            String rawPayload = event.getSetPayload();
            if (rawPayload == null || rawPayload.isBlank()) {
                throw new ScimException(500, null, "Internal server error");
            }
            Object body = parseCompletedPayload(rawPayload);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body);
        }

        if ("FAILED".equalsIgnoreCase(event.getStatus())) {
            Map<String, Object> failedSetPayload = parseFailedSetPayload(event.getSetPayload());
            if (failedSetPayload != null) {
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(failedSetPayload);
            }
            throw new ScimException(500, null, "Internal server error");
        }

        throw new ScimException(500, null, "Internal server error");
    }

    private Object parseCompletedPayload(String rawPayload) {
        try {
            return objectMapper.readValue(rawPayload, MAP_TYPE_REF);
        } catch (JsonProcessingException _) {
            return rawPayload;
        }
    }

    private Map<String, Object> parseFailedSetPayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isBlank()) {
            return null;
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(rawPayload, MAP_TYPE_REF);
            return (parsed != null && parsed.containsKey("events")) ? parsed : null;
        } catch (JsonProcessingException _) {
            return null;
        }
    }
}
