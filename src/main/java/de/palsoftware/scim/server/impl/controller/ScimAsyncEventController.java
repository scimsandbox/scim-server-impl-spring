package de.palsoftware.scim.server.impl.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import de.palsoftware.scim.server.impl.service.ScimAsyncEventService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
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

    private final ScimAsyncEventRepository asyncEventRepository;
    private final ObjectMapper objectMapper;
    private final ScimAsyncEventService asyncEventService;

    public ScimAsyncEventController(ScimAsyncEventRepository asyncEventRepository,
                                    ObjectMapper objectMapper) {
        this(asyncEventRepository, objectMapper, null);
    }

    @Autowired
    public ScimAsyncEventController(ScimAsyncEventRepository asyncEventRepository,
                                    ObjectMapper objectMapper,
                                    @Nullable ScimAsyncEventService asyncEventService) {
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

        if ("PENDING".equalsIgnoreCase(event.getStatus()) && asyncEventService != null) {
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
            try {
                Map<String, Object> setPayload = objectMapper.readValue(
                        rawPayload,
                        new TypeReference<Map<String, Object>>() {});
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(setPayload);
            } catch (Exception e) {
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(rawPayload);
            }
        }

        if ("FAILED".equalsIgnoreCase(event.getStatus())) {
            String rawPayload = event.getSetPayload();
            if (rawPayload != null && !rawPayload.isBlank()) {
                try {
                    Map<String, Object> setPayload = objectMapper.readValue(
                            rawPayload,
                            new TypeReference<Map<String, Object>>() {});
                    if (setPayload != null && setPayload.containsKey("events")) {
                        return ResponseEntity.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(setPayload);
                    }
                } catch (Exception ignored) {
                    // Fall through to 500 SCIM error when payload is not a SET JSON object
                }
            }
            throw new ScimException(500, null, "Internal server error");
        }

        throw new ScimException(500, null, "Internal server error");
    }
}
