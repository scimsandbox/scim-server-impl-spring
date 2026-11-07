package de.palsoftware.scim.server.impl.scim.projection;

import java.util.*;

/**
 * Deep SCIM 2.0 attribute projector per RFC 7644 §3.9 & §3.4.2.5.
 * Supports top-level attributes, dotted complex sub-attributes (e.g. name.givenName),
 * multi-valued complex sub-attributes (e.g. emails.value), and schema URN prefixes.
 */
public final class ScimAttributeProjector {

    private static final String USER_CORE_URN_COLON = "urn:ietf:params:scim:schemas:core:2.0:user:";
    private static final String USER_CORE_URN_DOT = "urn:ietf:params:scim:schemas:core:2.0:user.";
    private static final String GROUP_CORE_URN_COLON = "urn:ietf:params:scim:schemas:core:2.0:group:";
    private static final String GROUP_CORE_URN_DOT = "urn:ietf:params:scim:schemas:core:2.0:group.";
    private static final String ENTERPRISE_URN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String ENTERPRISE_URN_LOWER = ENTERPRISE_URN.toLowerCase(Locale.ROOT);

    private ScimAttributeProjector() {
    }

    private record ParsedAttrPath(String topKey, String subPath) {
    }

    public static void applyProjection(Map<String, Object> resource, String attributes, String excludedAttributes) {
        if (resource == null) {
            return;
        }
        // RFC 7643 §7: returned="never" attributes MUST never be returned
        removeCaseInsensitive(resource, "password");

        if (attributes != null && !attributes.isBlank()) {
            applyInclude(resource, parsePaths(attributes));
        } else if (excludedAttributes != null && !excludedAttributes.isBlank()) {
            applyExclude(resource, parsePaths(excludedAttributes));
        }
    }

    private static List<ParsedAttrPath> parsePaths(String csv) {
        List<ParsedAttrPath> paths = new ArrayList<>();
        for (String rawToken : csv.split(",")) {
            String token = rawToken.trim();
            if (token.isEmpty()) {
                continue;
            }
            paths.add(parseSinglePath(token));
        }
        return paths;
    }

    private static ParsedAttrPath parseSinglePath(String token) {
        String lower = token.toLowerCase(Locale.ROOT);

        // Enterprise extension URN
        if (lower.equals(ENTERPRISE_URN_LOWER)) {
            return new ParsedAttrPath(ENTERPRISE_URN, null);
        }
        if (lower.startsWith(ENTERPRISE_URN_LOWER + ":") || lower.startsWith(ENTERPRISE_URN_LOWER + ".")) {
            String rest = token.substring(ENTERPRISE_URN.length() + 1).trim();
            return new ParsedAttrPath(ENTERPRISE_URN, rest.isEmpty() ? null : rest);
        }

        // Strip core User / Group URN prefix if present
        String stripped = token;
        if (lower.startsWith(USER_CORE_URN_COLON) || lower.startsWith(USER_CORE_URN_DOT)) {
            stripped = token.substring(USER_CORE_URN_COLON.length());
        } else if (lower.startsWith(GROUP_CORE_URN_COLON) || lower.startsWith(GROUP_CORE_URN_DOT)) {
            stripped = token.substring(GROUP_CORE_URN_COLON.length());
        }

        // If another unknown extension URN is used with ':', split at the last ':'
        if (stripped.toLowerCase(Locale.ROOT).startsWith("urn:")) {
            int lastColon = stripped.lastIndexOf(':');
            if (lastColon > 0 && lastColon < stripped.length() - 1) {
                // Check if prefix before lastColon is itself a URN (contains ':')
                String prefix = stripped.substring(0, lastColon);
                if (prefix.indexOf(':') != prefix.lastIndexOf(':')) {
                    String rest = stripped.substring(lastColon + 1);
                    return new ParsedAttrPath(prefix, rest);
                }
            }
            return new ParsedAttrPath(stripped, null);
        }

        int dot = stripped.indexOf('.');
        if (dot > 0 && dot < stripped.length() - 1) {
            return new ParsedAttrPath(stripped.substring(0, dot), stripped.substring(dot + 1));
        }
        return new ParsedAttrPath(stripped, null);
    }

    private static void applyInclude(Map<String, Object> resource, List<ParsedAttrPath> paths) {
        Set<String> fullRetainLower = new HashSet<>();
        fullRetainLower.add("schemas");
        fullRetainLower.add("id");

        Map<String, List<String>> subPathsByTopLower = new LinkedHashMap<>();
        boolean metaExplicitlySubProjected = false;

        for (ParsedAttrPath p : paths) {
            String topLower = p.topKey().toLowerCase(Locale.ROOT);
            if ("password".equals(topLower)) {
                continue;
            }
            if (p.subPath() == null) {
                fullRetainLower.add(topLower);
            } else {
                if ("meta".equals(topLower)) {
                    metaExplicitlySubProjected = true;
                }
                subPathsByTopLower.computeIfAbsent(topLower, k -> new ArrayList<>()).add(p.subPath());
            }
        }

        // Preserve 'meta' unless specific 'meta.*' sub-attributes were requested without full 'meta'
        if (!metaExplicitlySubProjected) {
            fullRetainLower.add("meta");
        }

        Iterator<Map.Entry<String, Object>> it = resource.entrySet().iterator();
        Map<String, Object> updatedEntries = new LinkedHashMap<>();

        while (it.hasNext()) {
            Map.Entry<String, Object> entry = it.next();
            String key = entry.getKey();
            String keyLower = key.toLowerCase(Locale.ROOT);

            if (fullRetainLower.contains(keyLower)) {
                continue;
            }

            List<String> subPaths = subPathsByTopLower.get(keyLower);
            if (subPaths == null) {
                it.remove();
                continue;
            }

            Object projected = retainSubPaths(entry.getValue(), subPaths);
            if (projected == null) {
                it.remove();
            } else {
                updatedEntries.put(key, projected);
            }
        }

        resource.putAll(updatedEntries);
    }

    @SuppressWarnings("unchecked")
    private static Object retainSubPaths(Object current, List<String> subPaths) {
        if (current instanceof Map<?, ?> rawMap) {
            Map<String, Object> mapCopy = new LinkedHashMap<>();
            Set<String> fullSubLower = new HashSet<>();
            Map<String, List<String>> nestedByLower = new LinkedHashMap<>();

            for (String sp : subPaths) {
                int dot = sp.indexOf('.');
                if (dot > 0 && dot < sp.length() - 1) {
                    String head = sp.substring(0, dot).toLowerCase(Locale.ROOT);
                    String tail = sp.substring(dot + 1);
                    nestedByLower.computeIfAbsent(head, k -> new ArrayList<>()).add(tail);
                } else {
                    fullSubLower.add(sp.toLowerCase(Locale.ROOT));
                }
            }

            for (Map.Entry<?, ?> e : rawMap.entrySet()) {
                String k = String.valueOf(e.getKey());
                String kLower = k.toLowerCase(Locale.ROOT);
                if (fullSubLower.contains(kLower)) {
                    mapCopy.put(k, e.getValue());
                } else if (nestedByLower.containsKey(kLower)) {
                    Object nestedProjected = retainSubPaths(e.getValue(), nestedByLower.get(kLower));
                    if (nestedProjected != null) {
                        mapCopy.put(k, nestedProjected);
                    }
                }
            }
            return mapCopy.isEmpty() ? null : mapCopy;
        }

        if (current instanceof List<?> rawList) {
            List<Object> projectedList = new ArrayList<>(rawList.size());
            for (Object elem : rawList) {
                if (elem instanceof Map<?, ?>) {
                    Object projectedElem = retainSubPaths(elem, subPaths);
                    if (projectedElem != null) {
                        projectedList.add(projectedElem);
                    }
                }
            }
            return projectedList.isEmpty() ? null : projectedList;
        }

        return null;
    }

    private static void applyExclude(Map<String, Object> resource, List<ParsedAttrPath> paths) {
        for (ParsedAttrPath p : paths) {
            String topLower = p.topKey().toLowerCase(Locale.ROOT);
            // returned="always" attributes MUST NOT be excluded
            if ("schemas".equals(topLower) || "id".equals(topLower)) {
                continue;
            }
            if (p.subPath() == null) {
                removeCaseInsensitive(resource, p.topKey());
            } else {
                String actualKey = findKeyCaseInsensitive(resource, p.topKey());
                if (actualKey != null) {
                    Object updated = removeSubPath(resource.get(actualKey), p.subPath());
                    if (updated == null) {
                        resource.remove(actualKey);
                    } else {
                        resource.put(actualKey, updated);
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Object removeSubPath(Object current, String subPath) {
        if (current instanceof Map<?, ?> rawMap) {
            Map<String, Object> mapCopy = new LinkedHashMap<>((Map<String, Object>) rawMap);
            int dot = subPath.indexOf('.');
            if (dot > 0 && dot < subPath.length() - 1) {
                String head = subPath.substring(0, dot);
                String tail = subPath.substring(dot + 1);
                String actualHead = findKeyCaseInsensitive(mapCopy, head);
                if (actualHead != null) {
                    Object nestedUpdated = removeSubPath(mapCopy.get(actualHead), tail);
                    if (nestedUpdated == null) {
                        mapCopy.remove(actualHead);
                    } else {
                        mapCopy.put(actualHead, nestedUpdated);
                    }
                }
            } else {
                removeCaseInsensitive(mapCopy, subPath);
            }
            return mapCopy.isEmpty() ? null : mapCopy;
        }

        if (current instanceof List<?> rawList) {
            List<Object> updatedList = new ArrayList<>(rawList.size());
            for (Object elem : rawList) {
                if (elem instanceof Map<?, ?>) {
                    Object updatedElem = removeSubPath(elem, subPath);
                    if (updatedElem != null) {
                        updatedList.add(updatedElem);
                    }
                } else {
                    updatedList.add(elem);
                }
            }
            return updatedList.isEmpty() ? null : updatedList;
        }

        return current;
    }

    private static String findKeyCaseInsensitive(Map<String, Object> map, String target) {
        if (map.containsKey(target)) {
            return target;
        }
        for (String key : map.keySet()) {
            if (key.equalsIgnoreCase(target)) {
                return key;
            }
        }
        return null;
    }

    private static void removeCaseInsensitive(Map<String, Object> map, String target) {
        String key = findKeyCaseInsensitive(map, target);
        if (key != null) {
            map.remove(key);
        }
    }
}
