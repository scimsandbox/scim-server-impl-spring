package de.palsoftware.scim.server.impl.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.entity.ScimAsyncEvent;
import de.palsoftware.scim.server.impl.repository.ScimAsyncEventRepository;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.util.ScimPreferHeaderUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

    private final ScimAsyncEventRepository asyncEventRepository;
    private final ObjectMapper objectMapper;

    public ScimAsyncEventController(ScimAsyncEventRepository asyncEventRepository,
                                    ObjectMapper objectMapper) {
        this.asyncEventRepository = asyncEventRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Polls the status of an asynchronous operation transaction.
     *
     * @param workspaceId the workspace identifier
     * @param txnId       the transaction UUID
     * @param compat      optional compatibility segment (e.g. "ms")
     * @param request     the HTTP servlet request
     * @return 202 Accepted if PENDING, 200 OK with SET JSON if COMPLETED, 500 if FAILED, 404 if not found
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
            String location = baseUrl + "/Events/" + transactionId;
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .header(ScimPreferHeaderUtil.SET_TXN_HEADER, transactionId.toString())
                    .header("Location", location)
                    .build();
        }

        if ("COMPLETED".equalsIgnoreCase(event.getStatus())) {
            try {
                Map<String, Object> setPayload = objectMapper.readValue(
                        event.getSetPayload(),
                        new TypeReference<Map<String, Object>>() {});
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(setPayload);
            } catch (Exception e) {
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(event.getSetPayload());
            }
        }

        if ("FAILED".equalsIgnoreCase(event.getStatus())) {
            throw new ScimException(500, null, "Async operation failed: " + event.getSetPayload());
        }

        throw new ScimException(500, null, "Unknown event status: " + event.getStatus());
    }
}
