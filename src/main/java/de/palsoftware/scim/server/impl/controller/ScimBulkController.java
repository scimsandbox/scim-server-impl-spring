package de.palsoftware.scim.server.impl.controller;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.service.ScimGroupService;
import de.palsoftware.scim.server.impl.service.ScimUserService;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SCIM 2.0 Bulk Operations endpoint per RFC 7644 §3.7.
 */
@RestController
@RequestMapping({"/ws/{workspaceId}/scim/v2/Bulk", "/ws/{workspaceId}/scim/v2/{compat}/Bulk"})
public class ScimBulkController extends ScimBaseController {

    private static final Logger log = LoggerFactory.getLogger(ScimBulkController.class);

    private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");
    private static final String BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    private static final String ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final int MAX_OPERATIONS = 1000;
    public static final int MAX_PAYLOAD_SIZE = 1048576; // 1 MB per ServiceProviderConfig
    private static final String KEY_FAIL_ON_ERRORS = "failOnErrors";
    private static final String KEY_OPERATIONS = "Operations";
    private static final String KEY_STATUS = "status";
    private static final String KEY_RESPONSE = "response";
    private static final String KEY_LOCATION = "location";
    private static final String KEY_VERSION = "version";
    private static final String RESOURCE_USERS = "Users";
    private static final String RESOURCE_GROUPS = "Groups";

    private static final Pattern MULTIPLE_SLASHES = Pattern.compile("/+");
    private static final Pattern BULK_ID_TOKEN = Pattern.compile("bulkId:([^/?#\\s\"']+)");

    enum BulkResourceType {
        USERS,
        GROUPS
    }

    record BulkTarget(BulkResourceType type, UUID id) {}

    private record DeferredCycleRefs(
            List<Map<String, Object>> deferredGroupMembers,
            String enterpriseKey,
            Map<String, Object> deferredManagerMap) {
        boolean hasDeferredPatch() {
            return !deferredGroupMembers.isEmpty() || deferredManagerMap != null;
        }
    }

    private record ShellCycleState(
            int opIndex,
            BulkResourceType resourceType,
            UUID createdId,
            String bulkId,
            DeferredCycleRefs deferred) {}

    private final ScimUserService userService;
    private final ScimGroupService groupService;

    public ScimBulkController(ScimUserService userService, ScimGroupService groupService) {
        this.userService = userService;
        this.groupService = groupService;
    }

    @PostMapping
    @SuppressWarnings("unchecked")
    public ResponseEntity<Map<String, Object>> processBulk(
            @PathVariable String workspaceId,
            @RequestBody Map<String, Object> body,
            @PathVariable(name = "compat", required = false) String compat,
            HttpServletRequest request) {

        UUID wsId = resolveWorkspaceId(workspaceId);
        String baseUrl = buildBaseUrl(request, workspaceId, compat);

        List<Map<String, Object>> operations = validateBulkRequest(request, body);
        int failOnErrors = parseFailOnErrors(body.get(KEY_FAIL_ON_ERRORS));

        int n = operations.size();
        Map<String, String> bulkIdMap = new LinkedHashMap<>();
        Map<String, Object>[] resultsByIndex = new Map[n];
        boolean[] executed = new boolean[n];
        int errorCount = 0;

        // Build dependency graph for forward and circular bulkId references while preserving stateful order
        Map<String, Integer> postIndexByBulkId = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            Map<String, Object> op = operations.get(i);
            if ("POST".equalsIgnoreCase(asString(op.get("method")))) {
                String bid = asString(op.get("bulkId"));
                if (bid != null && !bid.isBlank() && !postIndexByBulkId.containsKey(bid)) {
                    postIndexByBulkId.put(bid, i);
                }
            }
        }

        List<Set<Integer>> adj = new ArrayList<>(n);
        int[] inDegree = new int[n];
        for (int i = 0; i < n; i++) {
            adj.add(new LinkedHashSet<>());
        }

        Map<String, Integer> lastOpOnTarget = new HashMap<>();
        for (int i = 0; i < n; i++) {
            Map<String, Object> op = operations.get(i);
            Set<String> refs = collectBulkIdReferences(op.get("path"), op.get("data"));
            for (String ref : refs) {
                Integer defIdx = postIndexByBulkId.get(ref);
                if (defIdx != null && defIdx != i && adj.get(defIdx).add(i)) {
                    inDegree[i]++;
                }
            }

            // Preserve relative order of PUT/PATCH/DELETE targeting the same resource path
            String method = asString(op.get("method"));
            if (method != null && !"POST".equalsIgnoreCase(method)) {
                String normTargetKey = canonicalTargetKey(asString(op.get("path")));
                if (normTargetKey != null) {
                    Integer prevIdx = lastOpOnTarget.put(normTargetKey, i);
                    if (prevIdx != null && prevIdx != i && adj.get(prevIdx).add(i)) {
                        inDegree[i]++;
                    }
                }
            }
        }

        PriorityQueue<Integer> readyQueue = new PriorityQueue<>();
        for (int i = 0; i < n; i++) {
            if (inDegree[i] == 0) {
                readyQueue.add(i);
            }
        }

        while (!readyQueue.isEmpty()) {
            int idx = readyQueue.poll();
            executed[idx] = true;
            Map<String, Object> result = processOperation(operations.get(idx), wsId, baseUrl, bulkIdMap);
            resultsByIndex[idx] = result;

            if (isErrorResult(result)) {
                errorCount++;
                if (shouldStopProcessing(failOnErrors, errorCount)) {
                    break;
                }
            }

            for (int dep : adj.get(idx)) {
                inDegree[dep]--;
                if (inDegree[dep] == 0) {
                    readyQueue.add(dep);
                }
            }
        }

        // Handle remaining unexecuted operations (circular POST bulkId references + downstream ops)
        if (!shouldStopProcessing(failOnErrors, errorCount)) {
            errorCount = processRemainingCyclicOperations(
                    operations, executed, resultsByIndex, postIndexByBulkId,
                    wsId, baseUrl, bulkIdMap, failOnErrors, errorCount);
        }

        List<Map<String, Object>> orderedResults = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            if (resultsByIndex[i] != null) {
                orderedResults.add(resultsByIndex[i]);
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:BulkResponse"));
        response.put(KEY_OPERATIONS, orderedResults);

        return ResponseEntity.ok()
                .contentType(SCIM_JSON)
                .body(response);
    }

    @SuppressWarnings("unchecked")
    private int processRemainingCyclicOperations(
            List<Map<String, Object>> operations,
            boolean[] executed,
            Map<String, Object>[] resultsByIndex,
            Map<String, Integer> postIndexByBulkId,
            UUID wsId,
            String baseUrl,
            Map<String, String> bulkIdMap,
            int failOnErrors,
            int errorCount) {

        int n = operations.size();
        Set<String> unresolvedBulkIds = new LinkedHashSet<>();
        List<Integer> cyclicPostIndices = new ArrayList<>();
        List<Integer> otherRemainingIndices = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            if (executed[i]) {
                continue;
            }
            Map<String, Object> op = operations.get(i);
            if ("POST".equalsIgnoreCase(asString(op.get("method")))) {
                cyclicPostIndices.add(i);
                String bid = asString(op.get("bulkId"));
                if (bid != null && !bid.isBlank()) {
                    unresolvedBulkIds.add(bid);
                }
            } else {
                otherRemainingIndices.add(i);
            }
        }

        if (!cyclicPostIndices.isEmpty()) {
            Map<Integer, ShellCycleState> deferredByIdx = new LinkedHashMap<>();

            // Pass 1: Create POST resources with cyclic member/manager references deferred
            for (int idx : cyclicPostIndices) {
                if (shouldStopProcessing(failOnErrors, errorCount)) {
                    break;
                }
                executed[idx] = true;
                Map<String, Object> origOp = operations.get(idx);
                Object rawData = origOp.get("data");
                if (!(rawData instanceof Map<?, ?> origDataMap)) {
                    Map<String, Object> result = processOperation(origOp, wsId, baseUrl, bulkIdMap);
                    resultsByIndex[idx] = result;
                    if (isErrorResult(result)) {
                        errorCount++;
                    }
                    continue;
                }

                Map<String, Object> strippedOp = new LinkedHashMap<>(origOp);
                Map<String, Object> strippedData = new LinkedHashMap<>((Map<String, Object>) origDataMap);
                DeferredCycleRefs deferred = stripUnresolvedCycleRefs(strippedData, unresolvedBulkIds);
                strippedOp.put("data", strippedData);

                // If stripping member/manager refs still leaves unresolved cycle bulkIds in data/path, report 409 Conflict
                Set<String> leftoverRefs = collectBulkIdReferences(strippedOp.get("path"), strippedData);
                leftoverRefs.retainAll(unresolvedBulkIds);
                if (!leftoverRefs.isEmpty()) {
                    Map<String, Object> conflictRes = buildConflictOperationResult(origOp,
                            "Circular bulkId reference cannot be resolved in non-deferrable attribute");
                    resultsByIndex[idx] = conflictRes;
                    errorCount++;
                    continue;
                }

                Map<String, Object> pass1Result = processOperation(strippedOp, wsId, baseUrl, bulkIdMap);
                resultsByIndex[idx] = pass1Result;
                if (isErrorResult(pass1Result)) {
                    errorCount++;
                } else if (deferred.hasDeferredPatch()) {
                    String bulkId = asString(origOp.get("bulkId"));
                    String createdIdStr = bulkId != null ? bulkIdMap.get(bulkId) : null;
                    String rawPath = asString(strippedOp.get("path"));
                    String resolvedPath = rawPath != null ? resolveBulkIdReferences(rawPath, bulkIdMap) : null;
                    BulkTarget target = tryParseBulkTarget(resolvedPath, false);
                    if (createdIdStr != null && target != null) {
                        deferredByIdx.put(idx, new ShellCycleState(
                                idx, target.type(), UUID.fromString(createdIdStr), bulkId, deferred));
                    }
                }
            }

            // Pre-validate Pass 2 shells: compensate any shell whose peer failed or was skipped in Pass 1
            boolean unresolvedFound = true;
            while (unresolvedFound) {
                unresolvedFound = false;
                Iterator<Map.Entry<Integer, ShellCycleState>> it = deferredByIdx.entrySet().iterator();
                while (it.hasNext()) {
                    ShellCycleState state = it.next().getValue();
                    String unresolvedToken = findUnresolvedDeferredToken(state.deferred(), bulkIdMap);
                    if (unresolvedToken != null) {
                        it.remove();
                        errorCount += failAndCompensateShell(
                                state, operations.get(state.opIndex()), wsId, bulkIdMap, resultsByIndex,
                                409, null, "Unresolved circular reference: " + unresolvedToken);
                        unresolvedFound = true;
                    }
                }
            }

            // Pass 2: Patch deferred cyclic group members and user managers on created shells
            List<ShellCycleState> patchedInPass2 = new ArrayList<>();
            for (ShellCycleState state : deferredByIdx.values()) {
                int idx = state.opIndex();
                DeferredCycleRefs deferred = state.deferred();
                Map<String, Object> origOp = operations.get(idx);
                UUID createdId = state.createdId();

                try {
                    String unresolvedToken = findUnresolvedDeferredToken(deferred, bulkIdMap);
                    if (unresolvedToken != null) {
                        throw new ScimException(409, null, "Unresolved circular reference: " + unresolvedToken);
                    }

                    if (!deferred.deferredGroupMembers().isEmpty()) {
                        List<Map<String, Object>> resolvedMembers = new ArrayList<>();
                        for (Map<String, Object> m : deferred.deferredGroupMembers()) {
                            Map<String, Object> rm = resolveBulkIdInData(m, bulkIdMap);
                            Object val = rm.get("value");
                            if (val instanceof String sv && sv.startsWith("bulkId:")) {
                                throw new ScimException(409, null, "Unresolved circular reference: " + sv);
                            }
                            Object refVal = rm.get("$ref");
                            if (refVal instanceof String sr && sr.contains("bulkId:")) {
                                throw new ScimException(409, null, "Unresolved circular reference: " + sr);
                            }
                            resolvedMembers.add(rm);
                        }
                        List<Map<String, Object>> patchOps = List.of(
                                Map.of("op", "add", "path", "members", "value", resolvedMembers));
                        ScimGroup updatedGroup = groupService.patchGroup(wsId, createdId, patchOps, null);
                        if (updatedGroup != null && updatedGroup.getVersion() != null) {
                            resultsByIndex[idx].put(KEY_VERSION, formatEtag(updatedGroup.getVersion()));
                        }
                    }

                    if (deferred.deferredManagerMap() != null) {
                        Map<String, Object> resolvedMgr = resolveBulkIdInData(deferred.deferredManagerMap(), bulkIdMap);
                        Object val = resolvedMgr.get("value");
                        if (val instanceof String sv && sv.startsWith("bulkId:")) {
                            throw new ScimException(409, null, "Unresolved circular manager reference: " + sv);
                        }
                        Object refVal = resolvedMgr.get("$ref");
                        if (refVal instanceof String sr && sr.contains("bulkId:")) {
                            throw new ScimException(409, null, "Unresolved circular manager reference: " + sr);
                        }
                        String mgrPath = ENTERPRISE_USER_SCHEMA + ":manager";
                        List<Map<String, Object>> patchOps = List.of(
                                Map.of("op", "replace", "path", mgrPath, "value", resolvedMgr));
                        ScimUser updatedUser = userService.patchUser(wsId, createdId, patchOps, null);
                        if (updatedUser != null && updatedUser.getVersion() != null) {
                            resultsByIndex[idx].put(KEY_VERSION, formatEtag(updatedUser.getVersion()));
                        }
                    }
                    patchedInPass2.add(state);
                } catch (ScimException e) {
                    errorCount += failAndCompensateShell(
                            state, origOp, wsId, bulkIdMap, resultsByIndex,
                            e.getHttpStatus(), e.getScimType(), e.getMessage());
                    errorCount += cascadeCompensateBrokenCyclePeers(
                            patchedInPass2, operations, wsId, bulkIdMap, resultsByIndex);
                } catch (Exception e) {
                    log.error("Failed Pass 2 circular reference resolution for bulkId={}", state.bulkId(), e);
                    errorCount += failAndCompensateShell(
                            state, origOp, wsId, bulkIdMap, resultsByIndex,
                            500, null, "Failed to resolve circular bulkId reference");
                    errorCount += cascadeCompensateBrokenCyclePeers(
                            patchedInPass2, operations, wsId, bulkIdMap, resultsByIndex);
                }
            }
        }

        for (int idx : otherRemainingIndices) {
            if (shouldStopProcessing(failOnErrors, errorCount)) {
                return errorCount;
            }
            executed[idx] = true;
            Map<String, Object> result = processOperation(operations.get(idx), wsId, baseUrl, bulkIdMap);
            resultsByIndex[idx] = result;
            if (isErrorResult(result)) {
                errorCount++;
            }
        }

        return errorCount;
    }

    @SuppressWarnings("unchecked")
    private DeferredCycleRefs stripUnresolvedCycleRefs(Map<String, Object> data, Set<String> unresolvedBulkIds) {
        List<Map<String, Object>> deferredMembers = new ArrayList<>();
        Object rawMembers = data.get("members");
        if (rawMembers instanceof List<?> memberList) {
            List<Object> keptMembers = new ArrayList<>();
            for (Object elem : memberList) {
                if (elem instanceof Map<?, ?> mMap && containsUnresolvedBulkId(mMap, unresolvedBulkIds)) {
                    deferredMembers.add(new LinkedHashMap<>((Map<String, Object>) mMap));
                    continue;
                }
                keptMembers.add(elem);
            }
            if (!deferredMembers.isEmpty()) {
                if (keptMembers.isEmpty()) {
                    data.remove("members");
                } else {
                    data.put("members", keptMembers);
                }
            }
        }

        String foundEntKey = null;
        Map<String, Object> deferredManager = null;
        for (String key : new ArrayList<>(data.keySet())) {
            if (ENTERPRISE_USER_SCHEMA.equalsIgnoreCase(key) && data.get(key) instanceof Map<?, ?> entMap) {
                Object mgrObj = entMap.get("manager");
                if (mgrObj instanceof Map<?, ?> mgrMap && containsUnresolvedBulkId(mgrMap, unresolvedBulkIds)) {
                    foundEntKey = key;
                    deferredManager = new LinkedHashMap<>((Map<String, Object>) mgrMap);
                    Map<String, Object> copyEnt = new LinkedHashMap<>((Map<String, Object>) entMap);
                    copyEnt.remove("manager");
                    data.put(key, copyEnt);
                }
            }
        }

        return new DeferredCycleRefs(deferredMembers, foundEntKey, deferredManager);
    }

    private static boolean containsUnresolvedBulkId(Map<?, ?> map, Set<String> unresolvedBulkIds) {
        for (String key : List.of("value", "$ref")) {
            Object raw = map.get(key);
            if (raw instanceof String s && s.contains("bulkId:")) {
                Matcher m = BULK_ID_TOKEN.matcher(s);
                while (m.find()) {
                    if (unresolvedBulkIds.contains(m.group(1))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static String findUnresolvedDeferredToken(DeferredCycleRefs deferred, Map<String, String> bulkIdMap) {
        Set<String> refs = new LinkedHashSet<>();
        collectRefsRecursive(deferred.deferredGroupMembers(), refs);
        collectRefsRecursive(deferred.deferredManagerMap(), refs);
        for (String ref : refs) {
            if (!bulkIdMap.containsKey(ref)) {
                return "bulkId:" + ref;
            }
        }
        return null;
    }

    private int failAndCompensateShell(ShellCycleState state, Map<String, Object> origOp, UUID wsId,
                                        Map<String, String> bulkIdMap, Map<String, Object>[] resultsByIndex,
                                        int httpStatus, String scimType, String detail) {
        compensateShellResource(wsId, state.resourceType(), state.createdId());
        if (state.bulkId() != null) {
            bulkIdMap.remove(state.bulkId());
        }
        resultsByIndex[state.opIndex()] = buildErrorOperationResult(origOp, httpStatus, scimType, detail);
        return 1;
    }

    private int cascadeCompensateBrokenCyclePeers(List<ShellCycleState> patchedInPass2,
                                                   List<Map<String, Object>> operations,
                                                   UUID wsId,
                                                   Map<String, String> bulkIdMap,
                                                   Map<String, Object>[] resultsByIndex) {
        int cascadedErrors = 0;
        boolean changed = true;
        while (changed) {
            changed = false;
            Iterator<ShellCycleState> it = patchedInPass2.iterator();
            while (it.hasNext()) {
                ShellCycleState peer = it.next();
                String unresolvedToken = findUnresolvedDeferredToken(peer.deferred(), bulkIdMap);
                if (unresolvedToken != null) {
                    it.remove();
                    cascadedErrors += failAndCompensateShell(
                            peer, operations.get(peer.opIndex()), wsId, bulkIdMap, resultsByIndex,
                            409, null, "Unresolved circular reference: " + unresolvedToken);
                    changed = true;
                }
            }
        }
        return cascadedErrors;
    }

    private void compensateShellResource(UUID wsId, BulkResourceType resourceType, UUID createdId) {
        if (resourceType == null || createdId == null) {
            return;
        }
        try {
            switch (resourceType) {
                case USERS -> userService.deleteUser(wsId, createdId);
                case GROUPS -> groupService.deleteGroup(wsId, createdId);
            }
        } catch (Exception cleanupEx) {
            log.warn("Best-effort cleanup of Pass 1 shell {} {} failed", resourceType, createdId, cleanupEx);
        }
    }

    private Map<String, Object> buildConflictOperationResult(Map<String, Object> op, String detail) {
        return buildErrorOperationResult(op, 409, null, detail);
    }

    private Map<String, Object> buildErrorOperationResult(Map<String, Object> op, int httpStatus,
                                                           String scimType, String detail) {
        Map<String, Object> res = new LinkedHashMap<>();
        String bulkId = asString(op.get("bulkId"));
        if (bulkId != null) {
            res.put("bulkId", bulkId);
        }
        String method = asString(op.get("method"));
        res.put("method", method != null ? method.trim().toUpperCase(Locale.ROOT) : "POST");
        String statusStr = String.valueOf(httpStatus);
        res.put(KEY_STATUS, statusStr);
        res.put(KEY_RESPONSE, buildError(statusStr, scimType, detail));
        return res;
    }

    private static Set<String> collectBulkIdReferences(Object pathObj, Object dataObj) {
        Set<String> refs = new LinkedHashSet<>();
        collectRefsRecursive(pathObj, refs);
        collectRefsRecursive(dataObj, refs);
        return refs;
    }

    private static void collectRefsRecursive(Object obj, Set<String> refs) {
        if (obj instanceof String s) {
            Matcher m = BULK_ID_TOKEN.matcher(s);
            while (m.find()) {
                refs.add(m.group(1));
            }
        } else if (obj instanceof Map<?, ?> map) {
            for (Object v : map.values()) {
                collectRefsRecursive(v, refs);
            }
        } else if (obj instanceof List<?> list) {
            for (Object item : list) {
                collectRefsRecursive(item, refs);
            }
        }
    }

    private static String canonicalTargetKey(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        try {
            List<String> segs = normalizeBulkPath(rawPath);
            if (segs.size() == 2) {
                return segs.get(0).toLowerCase(Locale.ROOT) + "/" + segs.get(1).toLowerCase(Locale.ROOT);
            }
        } catch (ScimException ignored) {
            // Invalid path handled during operation execution
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> validateBulkRequest(HttpServletRequest request, Map<String, Object> body) {
        long contentLength = request.getContentLengthLong();
        if (contentLength > MAX_PAYLOAD_SIZE) {
            throw new ScimException(413, null,
                    "Bulk request payload size exceeds maxPayloadSize of " + MAX_PAYLOAD_SIZE + " bytes");
        }

        int cachedBytes = extractCachedContentLength(request);
        if (cachedBytes > MAX_PAYLOAD_SIZE) {
            throw new ScimException(413, null,
                    "Bulk request payload size exceeds maxPayloadSize of " + MAX_PAYLOAD_SIZE + " bytes");
        }

        if (body == null) {
            throw new ScimException(400, "invalidSyntax", "Bulk request body is required");
        }

        if (contentLength < 0 && cachedBytes <= 0 && estimateJsonBytes(body, 0) > MAX_PAYLOAD_SIZE) {
            throw new ScimException(413, null,
                    "Bulk request payload size exceeds maxPayloadSize of " + MAX_PAYLOAD_SIZE + " bytes");
        }

        Object rawSchemas = body.get(KEY_SCHEMAS);
        if (!(rawSchemas instanceof List<?> schemasList) || !schemasList.contains(BULK_REQUEST_SCHEMA)) {
            throw new ScimException(400, "invalidValue", "Bulk request must include BulkRequest schema");
        }

        Object rawOps = body.get(KEY_OPERATIONS);
        if (!(rawOps instanceof List<?> opsList)) {
            throw new ScimException(400, "invalidValue", "Bulk request must contain Operations");
        }
        if (opsList.size() > MAX_OPERATIONS) {
            throw new ScimException(413, null,
                    "Bulk request exceeds maxOperations (" + MAX_OPERATIONS + ")");
        }

        List<Map<String, Object>> typedOps = new ArrayList<>(opsList.size());
        for (Object elem : opsList) {
            if (!(elem instanceof Map<?, ?> opMap)) {
                throw new ScimException(400, "invalidSyntax", "Each Bulk operation must be a JSON object");
            }
            typedOps.add((Map<String, Object>) opMap);
        }
        return typedOps;
    }

    private static int extractCachedContentLength(HttpServletRequest request) {
        ServletRequest current = request;
        while (current != null) {
            if (current instanceof ContentCachingRequestWrapper cachingWrapper) {
                return cachingWrapper.getContentAsByteArray().length;
            }
            if (current instanceof ServletRequestWrapper wrapper) {
                current = wrapper.getRequest();
            } else {
                break;
            }
        }
        return -1;
    }

    private static long estimateJsonBytes(Object value, long currentTotal) {
        if (currentTotal > MAX_PAYLOAD_SIZE) {
            return currentTotal;
        }
        if (value == null) {
            return currentTotal + 4;
        }
        if (value instanceof String s) {
            return currentTotal + 2 + s.getBytes(StandardCharsets.UTF_8).length;
        }
        if (value instanceof Number || value instanceof Boolean) {
            return currentTotal + value.toString().length();
        }
        if (value instanceof Map<?, ?> map) {
            long total = currentTotal + 2;
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    total += 1;
                }
                first = false;
                total = estimateJsonBytes(String.valueOf(entry.getKey()), total) + 1;
                total = estimateJsonBytes(entry.getValue(), total);
                if (total > MAX_PAYLOAD_SIZE) {
                    return total;
                }
            }
            return total;
        }
        if (value instanceof Iterable<?> iterable) {
            long total = currentTotal + 2;
            boolean first = true;
            for (Object elem : iterable) {
                if (!first) {
                    total += 1;
                }
                first = false;
                total = estimateJsonBytes(elem, total);
                if (total > MAX_PAYLOAD_SIZE) {
                    return total;
                }
            }
            return total;
        }
        return currentTotal + value.toString().getBytes(StandardCharsets.UTF_8).length;
    }

    private static int parseFailOnErrors(Object failOnErrorsObj) {
        if (failOnErrorsObj instanceof Number number) {
            return number.intValue();
        }
        return 0;
    }

    private static boolean isErrorResult(Map<String, Object> result) {
        String status = (String) result.get(KEY_STATUS);
        if (status == null) {
            return false;
        }
        try {
            return Integer.parseInt(status) >= 400;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean shouldStopProcessing(int failOnErrors, int errorCount) {
        return failOnErrors > 0 && errorCount >= failOnErrors;
    }

    private static String asString(Object v) {
        return v instanceof String s ? s : null;
    }

    private static String formatEtag(Long version) {
        return "W/\"" + version + "\"";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> processOperation(Map<String, Object> op, UUID wsId,
                                                   String baseUrl, Map<String, String> bulkIdMap) {
        String rawMethodStr = asString(op.get("method"));
        String method = rawMethodStr != null ? rawMethodStr.trim().toUpperCase(Locale.ROOT) : null;
        String path = asString(op.get("path"));
        String bulkId = asString(op.get("bulkId"));
        String version = asString(op.get(KEY_VERSION));
        if (version != null && version.isBlank()) {
            version = null;
        }
        Object rawData = op.get("data");

        Map<String, Object> result = new LinkedHashMap<>();
        if (bulkId != null) {
            result.put("bulkId", bulkId);
        }
        if (method != null && !method.isEmpty()) {
            result.put("method", method);
        }

        try {
            if (method == null || method.isEmpty()) {
                throw new ScimException(400, "invalidValue", "Operation method is required");
            }

            // Resolve bulkId references in path
            if (path != null) {
                path = resolveBulkIdReferences(path, bulkIdMap);
            }

            // Pre-populate location for non-POST operations targeting a valid resource path (RFC 7644 §3.7 / §3.7.3)
            if (!"POST".equals(method)) {
                BulkTarget preTarget = tryParseBulkTarget(path, true);
                if (preTarget != null && preTarget.id() != null) {
                    String resType = preTarget.type() == BulkResourceType.USERS ? RESOURCE_USERS : RESOURCE_GROUPS;
                    result.put(KEY_LOCATION, buildResourceLocation(baseUrl, resType, preTarget.id()));
                }
            }

            // Validate required 'data' attribute on POST, PUT, PATCH (RFC 7644 §3.7)
            Map<String, Object> data = null;
            if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                if (!(rawData instanceof Map<?, ?> dataMap)) {
                    throw new ScimException(400, "invalidSyntax",
                            "'data' attribute is required and must be a JSON object for " + method + " operations");
                }
                data = resolveBulkIdInData((Map<String, Object>) dataMap, bulkIdMap);
            }

            switch (method) {
                case "POST" -> result.putAll(handlePost(path, data, wsId, baseUrl, bulkId, bulkIdMap));
                case "PUT" -> result.putAll(handlePut(path, data, version, wsId, baseUrl));
                case "PATCH" -> result.putAll(handlePatch(path, data, version, wsId, baseUrl));
                case "DELETE" -> result.putAll(handleDelete(path, version, wsId, baseUrl));
                default -> {
                    result.put(KEY_STATUS, "400");
                    result.put(KEY_RESPONSE, buildError("400", "invalidValue", "Unsupported method: " + method));
                }
            }
        } catch (ScimException e) {
            if ("POST".equals(method)) {
                result.remove(KEY_LOCATION);
            }
            result.put(KEY_STATUS, String.valueOf(e.getHttpStatus()));
            result.put(KEY_RESPONSE, buildError(
                    String.valueOf(e.getHttpStatus()), e.getScimType(), e.getMessage()));
        } catch (Exception e) {
            log.error("Unhandled bulk operation failure for method={}, path={}, bulkId={}", method, path, bulkId, e);
            if ("POST".equals(method)) {
                result.remove(KEY_LOCATION);
            }
            result.put(KEY_STATUS, "500");
            result.put(KEY_RESPONSE, buildError("500", null, "Internal server error"));
        }

        return result;
    }

    private Map<String, Object> handlePost(String path, Map<String, Object> data, UUID wsId,
                                            String baseUrl, String bulkId, Map<String, String> bulkIdMap) {
        Map<String, Object> result = new LinkedHashMap<>();
        BulkTarget target = parseBulkTarget(path, false);

        if (bulkId == null || bulkId.isBlank()) {
            throw new ScimException(400, "invalidValue", "bulkId is required for POST operations");
        }

        switch (target.type()) {
            case USERS -> {
                ScimUser user = userService.createUser(wsId, data);
                result.put(KEY_STATUS, "201");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
                if (user.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(user.getVersion()));
                }
                bulkIdMap.put(bulkId, user.getId().toString());
            }
            case GROUPS -> {
                ScimGroup group = groupService.createGroup(wsId, data);
                result.put(KEY_STATUS, "201");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
                if (group.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(group.getVersion()));
                }
                bulkIdMap.put(bulkId, group.getId().toString());
            }
        }
        return result;
    }

    private Map<String, Object> handlePut(String path, Map<String, Object> data, String version,
                                           UUID wsId, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        BulkTarget target = parseBulkTarget(path, true);

        switch (target.type()) {
            case USERS -> {
                ScimUser user = userService.replaceUser(wsId, target.id(), data, version);
                result.put(KEY_STATUS, "200");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
                if (user.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(user.getVersion()));
                }
            }
            case GROUPS -> {
                ScimGroup group = groupService.replaceGroup(wsId, target.id(), data, version);
                result.put(KEY_STATUS, "200");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
                if (group.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(group.getVersion()));
                }
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> handlePatch(String path, Map<String, Object> data, String version,
                                             UUID wsId, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        BulkTarget target = parseBulkTarget(path, true);

        if (data.containsKey(KEY_SCHEMAS)) {
            Object rawPatchSchemas = data.get(KEY_SCHEMAS);
            if (!(rawPatchSchemas instanceof List<?> ps) || !ps.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp")) {
                throw new ScimException(400, "invalidSyntax", "Bulk PATCH data schemas must include PatchOp schema");
            }
        }

        List<Map<String, Object>> operations = List.of();
        if (data.containsKey(KEY_OPERATIONS) && data.get(KEY_OPERATIONS) != null) {
            Object rawOps = data.get(KEY_OPERATIONS);
            if (!(rawOps instanceof List<?> opsList)) {
                throw new ScimException(400, "invalidSyntax", "'Operations' in Bulk PATCH data must be a JSON array");
            }
            List<Map<String, Object>> validated = new ArrayList<>(opsList.size());
            for (Object elem : opsList) {
                if (!(elem instanceof Map<?, ?> m)) {
                    throw new ScimException(400, "invalidSyntax", "Each PATCH operation must be a JSON object");
                }
                validated.add((Map<String, Object>) m);
            }
            operations = validated;
        }

        switch (target.type()) {
            case USERS -> {
                ScimUser user = userService.patchUser(wsId, target.id(), operations, version);
                result.put(KEY_STATUS, "200");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, user.getId()));
                if (user.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(user.getVersion()));
                }
            }
            case GROUPS -> {
                ScimGroup group = groupService.patchGroup(wsId, target.id(), operations, version);
                result.put(KEY_STATUS, "200");
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, group.getId()));
                if (group.getVersion() != null) {
                    result.put(KEY_VERSION, formatEtag(group.getVersion()));
                }
            }
        }
        return result;
    }

    private Map<String, Object> handleDelete(String path, String version, UUID wsId, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        BulkTarget target = parseBulkTarget(path, true);

        switch (target.type()) {
            case USERS -> {
                if (version != null) {
                    userService.deleteUser(wsId, target.id(), version);
                } else {
                    userService.deleteUser(wsId, target.id());
                }
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_USERS, target.id()));
            }
            case GROUPS -> {
                if (version != null) {
                    groupService.deleteGroup(wsId, target.id(), version);
                } else {
                    groupService.deleteGroup(wsId, target.id());
                }
                result.put(KEY_LOCATION, buildResourceLocation(baseUrl, RESOURCE_GROUPS, target.id()));
            }
        }
        result.put(KEY_STATUS, "204");
        return result;
    }

    private BulkTarget tryParseBulkTarget(String rawPath, boolean isItemRequired) {
        try {
            return parseBulkTarget(rawPath, isItemRequired);
        } catch (ScimException ignored) {
            return null;
        }
    }

    private BulkTarget parseBulkTarget(String rawPath, boolean isItemRequired) {
        List<String> segments = normalizeBulkPath(rawPath);
        if (segments.isEmpty()) {
            throw new ScimException(400, "invalidPath", "Bulk path cannot be empty: " + rawPath);
        }

        BulkResourceType resourceType;
        if (RESOURCE_USERS.equalsIgnoreCase(segments.get(0))) {
            resourceType = BulkResourceType.USERS;
        } else if (RESOURCE_GROUPS.equalsIgnoreCase(segments.get(0))) {
            resourceType = BulkResourceType.GROUPS;
        } else {
            throw new ScimException(400, "invalidValue", "Unknown resource path: " + rawPath);
        }

        if (isItemRequired) {
            if (segments.size() != 2 || segments.get(1).isBlank()) {
                throw new ScimException(400, "invalidPath", "Bulk path must include resource ID: " + rawPath);
            }
            String idStr = segments.get(1);
            UUID id;
            try {
                id = UUID.fromString(idStr);
            } catch (IllegalArgumentException e) {
                throw new ScimException(400, "invalidValue", "Invalid resource ID: " + idStr);
            }
            if (!id.toString().equalsIgnoreCase(idStr)) {
                throw new ScimException(400, "invalidValue", "Invalid resource ID: " + idStr);
            }
            return new BulkTarget(resourceType, id);
        }

        if (segments.size() != 1) {
            throw new ScimException(400, "invalidPath", "Bulk POST must specify a resource type endpoint: " + rawPath);
        }

        return new BulkTarget(resourceType, null);
    }

    private static List<String> normalizeBulkPath(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return List.of();
        }
        String trimmed = rawPath.trim();
        int start = 0;
        int end = trimmed.length();
        while (start < end && trimmed.charAt(start) == '/') {
            start++;
        }
        while (end > start && trimmed.charAt(end - 1) == '/') {
            end--;
        }
        if (start >= end) {
            return List.of();
        }
        String stripped = trimmed.substring(start, end);
        String[] rawSegments = MULTIPLE_SLASHES.split(stripped);
        List<String> segments = new ArrayList<>(rawSegments.length);
        for (String seg : rawSegments) {
            if (seg.isEmpty()) {
                continue;
            }
            if (".".equals(seg) || "..".equals(seg)) {
                throw new ScimException(400, "invalidPath",
                        "Path traversal segments ('.' or '..') are not allowed: " + rawPath);
            }
            segments.add(seg);
        }
        return segments;
    }

    private String resolveBulkIdReferences(String path, Map<String, String> bulkIdMap) {
        return resolveString(path, bulkIdMap);
    }

    private Map<String, Object> resolveBulkIdInData(Map<String, Object> data, Map<String, String> bulkIdMap) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            resolved.put(entry.getKey(), resolveValue(entry.getValue(), bulkIdMap));
        }
        return resolved;
    }

    @SuppressWarnings("unchecked")
    private Object resolveValue(Object value, Map<String, String> bulkIdMap) {
        if (value instanceof String s) {
            return resolveString(s, bulkIdMap);
        } else if (value instanceof Map) {
            return resolveBulkIdInData((Map<String, Object>) value, bulkIdMap);
        } else if (value instanceof List) {
            return resolveList((List<Object>) value, bulkIdMap);
        } else {
            return value;
        }
    }

    private String resolveString(String s, Map<String, String> bulkIdMap) {
        if (s == null || !s.contains("bulkId:")) {
            return s;
        }
        Matcher m = BULK_ID_TOKEN.matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String ref = m.group(1);
            String replacement = bulkIdMap.get(ref);
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement != null ? replacement : m.group(0)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private List<Object> resolveList(List<Object> list, Map<String, String> bulkIdMap) {
        List<Object> resolvedList = new ArrayList<>(list.size());
        for (Object item : list) {
            resolvedList.add(resolveValue(item, bulkIdMap));
        }
        return resolvedList;
    }

    private Map<String, Object> buildError(String status, String scimType, String detail) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:Error"));
        error.put(KEY_STATUS, status);
        if (scimType != null) error.put("scimType", scimType);
        if (detail != null) error.put("detail", detail);
        return error;
    }

    private String buildResourceLocation(String baseUrl, String resourceType, UUID resourceId) {
        return baseUrl + "/" + resourceType + "/" + resourceId;
    }
}
