package de.palsoftware.scim.server.impl.scim.filter;

import de.palsoftware.scim.server.impl.model.*;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser.FilterNode;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;

import java.time.Instant;
import java.util.*;

/**
 * Evaluates SCIM {@link FilterNode} ASTs directly against {@link ScimUser} and {@link ScimGroup}
 * entities with exact RFC 7644 §3.4.2.2 same-element valuePath ({@code attr[subFilter]}) semantics,
 * {@code caseExact} fidelity, and cross-resource attribute absence handling.
 */
public final class ScimFilterEvaluator {

    private ScimFilterEvaluator() {
    }

    private static final Set<String> STANDARD_MULTI_SUB_ATTRS = Set.of(
            "value", "type", "primary", "display", "$ref"
    );

    private static final Set<String> ADDRESS_SUB_ATTRS = Set.of(
            "formatted", "streetaddress", "locality", "region", "postalcode", "country", "type", "primary"
    );

    private static final Set<String> NAME_SUB_ATTRS = Set.of(
            "formatted", "familyname", "givenname", "middlename", "honorificprefix", "honorificsuffix"
    );

    private static final Set<String> META_SUB_ATTRS = Set.of(
            "resourcetype", "created", "lastmodified", "location", "version"
    );

    private static final Set<String> ENTERPRISE_SUB_ATTRS = Set.of(
            "employeenumber", "costcenter", "organization", "division", "department",
            "manager", "manager.value", "manager.$ref", "manager.displayname"
    );

    private static final Set<String> USER_SCALAR_ATTRS = Set.of(
            "id", "username", "externalid", "displayname", "nickname", "profileurl",
            "title", "usertype", "preferredlanguage", "locale", "timezone", "active", "password", "schemas"
    );

    private static final Set<String> GROUP_SCALAR_ATTRS = Set.of(
            "id", "displayname", "externalid", "schemas"
    );

    public static void validateAst(FilterNode node, boolean isUser, String parentAttr) {
        if (node == null) return;
        switch (node) {
            case FilterNode.AndNode n -> {
                validateAst(n.left(), isUser, parentAttr);
                validateAst(n.right(), isUser, parentAttr);
            }
            case FilterNode.OrNode n -> {
                validateAst(n.left(), isUser, parentAttr);
                validateAst(n.right(), isUser, parentAttr);
            }
            case FilterNode.NotNode n -> validateAst(n.inner(), isUser, parentAttr);
            case FilterNode.ValuePathNode n -> {
                if (parentAttr != null) {
                    // Nested valuePath inside enterpriseUser[manager[...]]
                    String combined = parentAttr + "." + n.parentAttr();
                    validateValuePathParent(combined, n.inner(), isUser);
                } else {
                    validateValuePathParent(n.parentAttr(), n.inner(), isUser);
                }
            }
            case FilterNode.PresenceNode n -> validateLeafAttribute(n.attrPath(), "pr", null, false, isUser, parentAttr);
            case FilterNode.ComparisonNode n -> validateLeafAttribute(n.attrPath(), n.operator(), n.value(), n.quoted(), isUser, parentAttr);
        }
    }

    private static void validateValuePathParent(String rawParent, FilterNode inner, boolean isUser) {
        if (ScimFilterParser.isOtherResourceAttribute(rawParent, isUser)) {
            String strippedOther = ScimFilterParser.stripCoreUrnPrefix(rawParent, !isUser).toLowerCase(Locale.ROOT);
            validateAst(inner, !isUser, strippedOther);
            return;
        }
        String stripped = ScimFilterParser.stripCoreUrnPrefix(rawParent, isUser).toLowerCase(Locale.ROOT);
        if (isUser) {
            if (ScimFilterParser.JSON_COLLECTIONS.contains(stripped)
                    || "groups".equals(stripped)
                    || "name".equals(stripped)
                    || "meta".equals(stripped)
                    || ScimFilterParser.ENTERPRISE_URN.equals(stripped)
                    || (ScimFilterParser.ENTERPRISE_URN_PREFIX + "manager").equals(stripped)) {
                validateAst(inner, true, stripped);
                return;
            }
        } else {
            if ("members".equals(stripped) || "meta".equals(stripped)) {
                validateAst(inner, false, stripped);
                return;
            }
        }
        throw new ScimException(400, "invalidFilter", "Invalid valuePath attribute: " + rawParent);
    }

    private static void validateLeafAttribute(String rawAttr, String op, String val, boolean quoted, boolean isUser, String parentAttr) {
        String fullRaw = parentAttr != null
                ? (ScimFilterParser.ENTERPRISE_URN.equals(parentAttr) ? parentAttr + ":" + rawAttr : parentAttr + "." + rawAttr)
                : rawAttr;

        if (ScimFilterParser.isOtherResourceAttribute(fullRaw, isUser)) {
            return;
        }

        String stripped = ScimFilterParser.stripCoreUrnPrefix(fullRaw, isUser);
        String lower = stripped.toLowerCase(Locale.ROOT);

        if (isUser) {
            validateUserLeaf(lower, stripped, op, val);
        } else {
            validateGroupLeaf(lower, stripped, op, val);
        }
    }

    private static void validateUserLeaf(String lower, String displayAttr, String op, String val) {
        if ((ScimFilterParser.JSON_COLLECTIONS.contains(lower) && !"addresses".equals(lower)) || "groups".equals(lower)) {
            if ("pr".equals(op)) {
                return;
            }
            validateUserLeaf(lower + ".value", displayAttr, op, val);
            return;
        }
        if ("name".equals(lower) || "meta".equals(lower) || ScimFilterParser.ENTERPRISE_URN.equals(lower)
                || "addresses".equals(lower)
                || (ScimFilterParser.ENTERPRISE_URN_PREFIX + "manager").equals(lower)) {
            if (!"pr".equals(op) && !(ScimFilterParser.ENTERPRISE_URN_PREFIX + "manager").equals(lower)) {
                throw new ScimException(400, "invalidFilter", "Operator '" + op + "' is not supported on complex/multi-valued attribute: " + displayAttr);
            }
            return;
        }
        if (lower.startsWith("name.")) {
            String sub = lower.substring(5);
            if (!NAME_SUB_ATTRS.contains(sub)) {
                throw new ScimException(400, "invalidFilter", "Unknown name sub-attribute: " + sub);
            }
            return;
        }
        if (lower.startsWith("meta.")) {
            String sub = lower.substring(5);
            if (!META_SUB_ATTRS.contains(sub)) {
                throw new ScimException(400, "invalidFilter", "Unknown meta attribute: " + sub);
            }
            if (("created".equals(sub) || "lastmodified".equals(sub)) && !"pr".equals(op)) {
                validateDateTimeOperatorAndValue(op, val, displayAttr);
            }
            return;
        }
        if (lower.startsWith(ScimFilterParser.ENTERPRISE_URN_PREFIX)) {
            String sub = lower.substring(ScimFilterParser.ENTERPRISE_URN_PREFIX.length());
            if (!ENTERPRISE_SUB_ATTRS.contains(sub)) {
                throw new ScimException(400, "invalidFilter", "Unknown enterprise attribute: " + sub);
            }
            return;
        }
        if (lower.contains(".")) {
            String[] parts = lower.split("\\.", 2);
            if (ScimFilterParser.JSON_COLLECTIONS.contains(parts[0])) {
                Set<String> allowed = "addresses".equals(parts[0]) ? ADDRESS_SUB_ATTRS : STANDARD_MULTI_SUB_ATTRS;
                if (!allowed.contains(parts[1])) {
                    throw new ScimException(400, "invalidFilter", "Unknown sub-attribute '" + parts[1] + "' on " + parts[0]);
                }
                if ("primary".equals(parts[1]) && !"pr".equals(op)) {
                    validateBooleanOperatorAndValue(op, val, displayAttr);
                } else if (!"pr".equals(op) && Set.of("gt", "ge", "lt", "le").contains(op)) {
                    throw new ScimException(400, "invalidFilter", "Operator " + op + " not supported for JSON collections");
                }
                return;
            }
            if ("groups".equals(parts[0])) {
                if (!STANDARD_MULTI_SUB_ATTRS.contains(parts[1]) || "primary".equals(parts[1])) {
                    throw new ScimException(400, "invalidFilter", "Unknown groups sub-attribute: " + parts[1]);
                }
                return;
            }
        }
        if (!USER_SCALAR_ATTRS.contains(lower)) {
            throw new ScimException(400, "invalidFilter", "Unknown attribute: " + displayAttr);
        }
        if ("active".equals(lower) && !"pr".equals(op)) {
            validateBooleanOperatorAndValue(op, val, displayAttr);
        } else if ("id".equals(lower) && !"pr".equals(op)) {
            validateUuidOperatorAndValue(op, val, displayAttr);
        }
    }

    private static void validateGroupLeaf(String lower, String displayAttr, String op, String val) {
        if ("members".equals(lower)) {
            if ("pr".equals(op)) {
                return;
            }
            validateGroupLeaf("members.value", displayAttr, op, val);
            return;
        }
        if ("meta".equals(lower)) {
            if (!"pr".equals(op)) {
                throw new ScimException(400, "invalidFilter", "Operator '" + op + "' is not supported on complex attribute: " + displayAttr);
            }
            return;
        }
        if (lower.startsWith("meta.")) {
            String sub = lower.substring(5);
            if (!META_SUB_ATTRS.contains(sub)) {
                throw new ScimException(400, "invalidFilter", "Unknown meta attribute: " + sub);
            }
            if (("created".equals(sub) || "lastmodified".equals(sub)) && !"pr".equals(op)) {
                validateDateTimeOperatorAndValue(op, val, displayAttr);
            }
            return;
        }
        if (lower.startsWith("members.")) {
            String sub = lower.substring(8);
            if (!Set.of("value", "$ref", "type", "display").contains(sub)) {
                throw new ScimException(400, "invalidFilter", "Unknown members sub-attribute: " + sub);
            }
            return;
        }
        if (!GROUP_SCALAR_ATTRS.contains(lower)) {
            throw new ScimException(400, "invalidFilter", "Unknown attribute: " + displayAttr);
        }
        if ("id".equals(lower) && !"pr".equals(op)) {
            validateUuidOperatorAndValue(op, val, displayAttr);
        }
    }

    private static void validateBooleanOperatorAndValue(String op, String val, String attrPath) {
        if (!"eq".equals(op) && !"ne".equals(op)) {
            throw new ScimException(400, "invalidFilter", "Comparison operator '" + op + "' is not supported for boolean attribute '" + attrPath + "'");
        }
        if (!"true".equalsIgnoreCase(val) && !"false".equalsIgnoreCase(val)) {
            throw new ScimException(400, "invalidFilter", "Invalid boolean value for attribute '" + attrPath + "': " + val);
        }
    }

    private static void validateDateTimeOperatorAndValue(String op, String val, String attrPath) {
        if ("co".equals(op) || "sw".equals(op) || "ew".equals(op)) {
            throw new ScimException(400, "invalidFilter", "Operator '" + op + "' is not supported for attribute: " + attrPath);
        }
        if (ScimFilterParser.parseDateTime(val) == null) {
            throw new ScimException(400, "invalidFilter", "Invalid dateTime format for attribute '" + attrPath + "': " + val);
        }
    }

    private static void validateUuidOperatorAndValue(String op, String val, String attrPath) {
        if (!"eq".equals(op) && !"ne".equals(op)) {
            throw new ScimException(400, "invalidFilter", "Operator '" + op + "' is not supported for attribute: " + attrPath);
        }
        try {
            UUID u = UUID.fromString(val);
            if (!u.toString().equalsIgnoreCase(val)) {
                throw new ScimException(400, "invalidFilter", "Invalid UUID format for attribute '" + attrPath + "': " + val);
            }
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidFilter", "Invalid UUID format for attribute '" + attrPath + "': " + val, e);
        }
    }

    // ── RUNTIME EVALUATION ────────────────────────────────

    public static boolean matchesUser(ScimUser user, List<Map<String, Object>> userGroups, FilterNode node) {
        if (node == null) return true;
        return switch (node) {
            case FilterNode.AndNode n -> matchesUser(user, userGroups, n.left()) && matchesUser(user, userGroups, n.right());
            case FilterNode.OrNode n -> matchesUser(user, userGroups, n.left()) || matchesUser(user, userGroups, n.right());
            case FilterNode.NotNode n -> !matchesUser(user, userGroups, n.inner());
            case FilterNode.ValuePathNode n -> evalUserValuePath(user, userGroups, n.parentAttr(), n.inner());
            case FilterNode.PresenceNode n -> evalUserPresence(user, userGroups, n.attrPath());
            case FilterNode.ComparisonNode n -> evalUserComparison(user, userGroups, n.attrPath(), n.operator(), n.value());
        };
    }

    public static boolean matchesGroup(ScimGroup group, FilterNode node) {
        if (node == null) return true;
        return switch (node) {
            case FilterNode.AndNode n -> matchesGroup(group, n.left()) && matchesGroup(group, n.right());
            case FilterNode.OrNode n -> matchesGroup(group, n.left()) || matchesGroup(group, n.right());
            case FilterNode.NotNode n -> !matchesGroup(group, n.inner());
            case FilterNode.ValuePathNode n -> evalGroupValuePath(group, n.parentAttr(), n.inner());
            case FilterNode.PresenceNode n -> evalGroupPresence(group, n.attrPath());
            case FilterNode.ComparisonNode n -> evalGroupComparison(group, n.attrPath(), n.operator(), n.value());
        };
    }

    private static boolean evalUserValuePath(ScimUser user, List<Map<String, Object>> userGroups, String rawParent, FilterNode inner) {
        if (ScimFilterParser.isOtherResourceAttribute(rawParent, true)) {
            return false;
        }
        String parent = ScimFilterParser.stripCoreUrnPrefix(rawParent, true).toLowerCase(Locale.ROOT);
        List<Map<String, Object>> elements = extractUserCollectionElements(user, userGroups, parent);
        for (Map<String, Object> elem : elements) {
            if (evalElementNode(elem, parent, inner)) {
                return true;
            }
        }
        return false;
    }

    private static boolean evalGroupValuePath(ScimGroup group, String rawParent, FilterNode inner) {
        if (ScimFilterParser.isOtherResourceAttribute(rawParent, false)) {
            return false;
        }
        String parent = ScimFilterParser.stripCoreUrnPrefix(rawParent, false).toLowerCase(Locale.ROOT);
        if ("members".equals(parent)) {
            if (group.getMembers() == null) return false;
            for (ScimGroupMembership m : group.getMembers()) {
                Map<String, Object> elem = memberToEvalMap(m);
                if (evalElementNode(elem, "members", inner)) {
                    return true;
                }
            }
            return false;
        }
        if ("meta".equals(parent)) {
            Map<String, Object> meta = buildMetaMap("Group", group.getCreatedAt(), group.getLastModified(), group.getVersion());
            return evalElementNode(meta, "meta", inner);
        }
        return false;
    }

    private static boolean evalElementNode(Map<String, Object> elem, String parentKey, FilterNode node) {
        return switch (node) {
            case FilterNode.AndNode n -> evalElementNode(elem, parentKey, n.left()) && evalElementNode(elem, parentKey, n.right());
            case FilterNode.OrNode n -> evalElementNode(elem, parentKey, n.left()) || evalElementNode(elem, parentKey, n.right());
            case FilterNode.NotNode n -> !evalElementNode(elem, parentKey, n.inner());
            case FilterNode.ValuePathNode n -> {
                Object subObj = elem.get(n.parentAttr().toLowerCase(Locale.ROOT));
                if (subObj instanceof Map<?, ?> subMap) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> castSub = (Map<String, Object>) subMap;
                    yield evalElementNode(castSub, parentKey + "." + n.parentAttr().toLowerCase(Locale.ROOT), n.inner());
                }
                yield false;
            }
            case FilterNode.PresenceNode n -> {
                Object v = lookupElementValue(elem, n.attrPath());
                yield v != null && (!(v instanceof String s) || !s.isEmpty());
            }
            case FilterNode.ComparisonNode n -> {
                Object v = lookupElementValue(elem, n.attrPath());
                if (v == null) yield false;
                boolean caseExact = isElementAttrCaseExact(parentKey, n.attrPath());
                yield compareAttributeValue(n.attrPath(), v, n.operator(), n.value(), caseExact);
            }
        };
    }

    private static Object lookupElementValue(Map<String, Object> elem, String rawSubAttr) {
        String key = rawSubAttr.toLowerCase(Locale.ROOT);
        if (elem.containsKey(key)) {
            return elem.get(key);
        }
        if (key.contains(".")) {
            String[] parts = key.split("\\.", 2);
            Object nested = elem.get(parts[0]);
            if (nested instanceof Map<?, ?> nestedMap) {
                return nestedMap.get(parts[1]);
            }
        }
        return null;
    }

    private static boolean isElementAttrCaseExact(String parentKey, String subAttr) {
        String sub = subAttr.toLowerCase(Locale.ROOT);
        if ("$ref".equals(sub) || "location".equals(sub) || "version".equals(sub)) {
            return true;
        }
        if ("value".equals(sub) && ("photos".equals(parentKey) || "x509certificates".equals(parentKey))) {
            return true;
        }
        if (parentKey.startsWith(ScimFilterParser.ENTERPRISE_URN) && ("manager.value".equals(sub) || "manager.$ref".equals(sub))) {
            return true;
        }
        return false;
    }

    private static List<Map<String, Object>> extractUserCollectionElements(ScimUser u, List<Map<String, Object>> userGroups, String parent) {
        List<Map<String, Object>> list = new ArrayList<>();
        switch (parent) {
            case "emails" -> {
                if (u.getEmails() != null) {
                    for (ScimUserEmail e : u.getEmails()) {
                        list.add(standardItemMap(e.getValue(), e.getType(), e.isPrimaryFlag(), e.getDisplay(), null));
                    }
                }
            }
            case "phonenumbers" -> {
                if (u.getPhoneNumbers() != null) {
                    for (ScimUserPhoneNumber p : u.getPhoneNumbers()) {
                        list.add(standardItemMap(p.getValue(), p.getType(), p.isPrimaryFlag(), p.getDisplay(), null));
                    }
                }
            }
            case "ims" -> {
                if (u.getIms() != null) {
                    for (ScimUserIm im : u.getIms()) {
                        list.add(standardItemMap(im.getValue(), im.getType(), im.isPrimaryFlag(), im.getDisplay(), null));
                    }
                }
            }
            case "photos" -> {
                if (u.getPhotos() != null) {
                    for (ScimUserPhoto ph : u.getPhotos()) {
                        list.add(standardItemMap(ph.getValue(), ph.getType(), ph.isPrimaryFlag(), ph.getDisplay(), ph.getValue()));
                    }
                }
            }
            case "entitlements" -> {
                if (u.getEntitlements() != null) {
                    for (ScimUserEntitlement ent : u.getEntitlements()) {
                        list.add(standardItemMap(ent.getValue(), ent.getType(), ent.isPrimaryFlag(), ent.getDisplay(), null));
                    }
                }
            }
            case "roles" -> {
                if (u.getRoles() != null) {
                    for (ScimUserRole r : u.getRoles()) {
                        list.add(standardItemMap(r.getValue(), r.getType(), r.isPrimaryFlag(), r.getDisplay(), null));
                    }
                }
            }
            case "x509certificates" -> {
                if (u.getX509Certificates() != null) {
                    for (ScimUserX509Certificate c : u.getX509Certificates()) {
                        list.add(standardItemMap(c.getValue(), c.getType(), c.isPrimaryFlag(), c.getDisplay(), null));
                    }
                }
            }
            case "addresses" -> {
                if (u.getAddresses() != null) {
                    for (ScimUserAddress a : u.getAddresses()) {
                        list.add(toAddressElementMap(a));
                    }
                }
            }
            case "groups" -> {
                if (userGroups != null) {
                    for (Map<String, Object> g : userGroups) {
                        Map<String, Object> m = new HashMap<>();
                        for (Map.Entry<String, Object> e : g.entrySet()) {
                            m.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
                        }
                        list.add(m);
                    }
                }
            }
            case "name" -> {
                Map<String, Object> m = new HashMap<>();
                if (u.getNameFormatted() != null) m.put("formatted", u.getNameFormatted());
                if (u.getNameFamilyName() != null) m.put("familyname", u.getNameFamilyName());
                if (u.getNameGivenName() != null) m.put("givenname", u.getNameGivenName());
                if (u.getNameMiddleName() != null) m.put("middlename", u.getNameMiddleName());
                if (u.getNameHonorificPrefix() != null) m.put("honorificprefix", u.getNameHonorificPrefix());
                if (u.getNameHonorificSuffix() != null) m.put("honorificsuffix", u.getNameHonorificSuffix());
                if (!m.isEmpty()) list.add(m);
            }
            case "meta" -> list.add(buildMetaMap("User", u.getCreatedAt(), u.getLastModified(), u.getVersion()));
            case ScimFilterParser.ENTERPRISE_URN -> {
                Map<String, Object> m = new HashMap<>();
                if (u.getEnterpriseEmployeeNumber() != null) m.put("employeenumber", u.getEnterpriseEmployeeNumber());
                if (u.getEnterpriseCostCenter() != null) m.put("costcenter", u.getEnterpriseCostCenter());
                if (u.getEnterpriseOrganization() != null) m.put("organization", u.getEnterpriseOrganization());
                if (u.getEnterpriseDivision() != null) m.put("division", u.getEnterpriseDivision());
                if (u.getEnterpriseDepartment() != null) m.put("department", u.getEnterpriseDepartment());
                if (u.getEnterpriseManagerValue() != null) {
                    Map<String, Object> mgr = new HashMap<>();
                    mgr.put("value", u.getEnterpriseManagerValue());
                    mgr.put("$ref", (u.getEnterpriseManagerRef() != null && !u.getEnterpriseManagerRef().isBlank())
                            ? u.getEnterpriseManagerRef()
                            : "/Users/" + u.getEnterpriseManagerValue());
                    if (u.getEnterpriseManagerDisplay() != null) mgr.put("displayname", u.getEnterpriseManagerDisplay());
                    m.put("manager", mgr);
                }
                if (!m.isEmpty()) list.add(m);
            }
            case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:manager" -> {
                if (u.getEnterpriseManagerValue() != null) {
                    Map<String, Object> mgr = new HashMap<>();
                    mgr.put("value", u.getEnterpriseManagerValue());
                    mgr.put("$ref", (u.getEnterpriseManagerRef() != null && !u.getEnterpriseManagerRef().isBlank())
                            ? u.getEnterpriseManagerRef()
                            : "/Users/" + u.getEnterpriseManagerValue());
                    if (u.getEnterpriseManagerDisplay() != null) mgr.put("displayname", u.getEnterpriseManagerDisplay());
                    list.add(mgr);
                }
            }
            default -> {
            }
        }
        return list;
    }

    public static boolean matchesCollectionElement(Map<String, Object> elem, String parentKey, FilterNode innerNode) {
        return evalElementNode(elem, parentKey.toLowerCase(Locale.ROOT), innerNode);
    }

    public static Map<String, Object> toStandardElementMap(String value, String type, boolean primary, String display, String ref) {
        return standardItemMap(value, type, primary, display, ref);
    }

    public static Map<String, Object> toAddressElementMap(ScimUserAddress a) {
        Map<String, Object> m = new HashMap<>(8);
        if (a.getFormatted() != null) m.put("formatted", a.getFormatted());
        if (a.getStreetAddress() != null) m.put("streetaddress", a.getStreetAddress());
        if (a.getLocality() != null) m.put("locality", a.getLocality());
        if (a.getRegion() != null) m.put("region", a.getRegion());
        if (a.getPostalCode() != null) m.put("postalcode", a.getPostalCode());
        if (a.getCountry() != null) m.put("country", a.getCountry());
        if (a.getType() != null) m.put("type", a.getType());
        m.put("primary", a.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> standardItemMap(String value, String type, boolean primary, String display, String ref) {
        Map<String, Object> m = new HashMap<>(6);
        if (value != null) m.put("value", value);
        if (type != null) m.put("type", type);
        m.put("primary", primary);
        if (display != null) m.put("display", display);
        if (ref != null) m.put("$ref", ref);
        return m;
    }

    private static Map<String, Object> memberToEvalMap(ScimGroupMembership m) {
        Map<String, Object> map = new HashMap<>(5);
        if (m.getMemberValue() != null) {
            map.put("value", m.getMemberValue().toString());
            String t = m.getMemberType();
            if (t != null && !t.isBlank()) {
                map.put("type", t);
                map.put("$ref", ("Group".equalsIgnoreCase(t) ? "/Groups/" : "/Users/") + m.getMemberValue());
            } else {
                map.put("$ref", "/Users/" + m.getMemberValue());
            }
        }
        if (m.getDisplay() != null) {
            map.put("display", m.getDisplay());
        }
        return map;
    }

    private static Map<String, Object> buildMetaMap(String resourceType, Instant created, Instant lastMod, Long version) {
        Map<String, Object> m = new HashMap<>();
        m.put("resourcetype", resourceType);
        if (created != null) m.put("created", created);
        Instant effectiveMod = (version == null || version == 0L) ? created : lastMod;
        if (effectiveMod != null) m.put("lastmodified", effectiveMod);
        m.put("version", "W/\"" + (version != null ? version : 0L) + "\"");
        return m;
    }

    private static boolean evalUserPresence(ScimUser u, List<Map<String, Object>> userGroups, String rawAttr) {
        if (ScimFilterParser.isOtherResourceAttribute(rawAttr, true)) {
            return false;
        }
        String stripped = ScimFilterParser.stripCoreUrnPrefix(rawAttr, true).toLowerCase(Locale.ROOT);
        if (ScimFilterParser.JSON_COLLECTIONS.contains(stripped)
                || "groups".equals(stripped)
                || "name".equals(stripped)
                || "meta".equals(stripped)
                || ScimFilterParser.ENTERPRISE_URN.equals(stripped)
                || (ScimFilterParser.ENTERPRISE_URN_PREFIX + "manager").equals(stripped)) {
            return !extractUserCollectionElements(u, userGroups, stripped).isEmpty();
        }
        if (stripped.contains(".")) {
            String[] parts = stripped.split("\\.", 2);
            if (ScimFilterParser.JSON_COLLECTIONS.contains(parts[0]) || "groups".equals(parts[0])) {
                for (Map<String, Object> elem : extractUserCollectionElements(u, userGroups, parts[0])) {
                    if (lookupElementValue(elem, parts[1]) != null) return true;
                }
                return false;
            }
        }
        return extractUserScalarValue(u, stripped) != null;
    }

    private static boolean evalUserComparison(ScimUser u, List<Map<String, Object>> userGroups, String rawAttr, String op, String target) {
        if (ScimFilterParser.isOtherResourceAttribute(rawAttr, true)) {
            return false;
        }
        String stripped = ScimFilterParser.stripCoreUrnPrefix(rawAttr, true).toLowerCase(Locale.ROOT);
        if ((ScimFilterParser.JSON_COLLECTIONS.contains(stripped) && !"addresses".equals(stripped)) || "groups".equals(stripped)) {
            stripped = stripped + ".value";
        }
        if (stripped.contains(".")) {
            String[] parts = stripped.split("\\.", 2);
            if (ScimFilterParser.JSON_COLLECTIONS.contains(parts[0]) || "groups".equals(parts[0])) {
                List<Map<String, Object>> elems = extractUserCollectionElements(u, userGroups, parts[0]);
                boolean caseExact = ScimFilterParser.isJsonSubAttributeCaseExact(parts[0], parts[1]);
                if ("ne".equals(op)) {
                    for (Map<String, Object> elem : elems) {
                        Object v = lookupElementValue(elem, parts[1]);
                        if (v != null && compareAttributeValue(parts[1], v, "eq", target, caseExact)) {
                            return false;
                        }
                    }
                    return true;
                }
                for (Map<String, Object> elem : elems) {
                    Object v = lookupElementValue(elem, parts[1]);
                    if (v != null && compareAttributeValue(parts[1], v, op, target, caseExact)) {
                        return true;
                    }
                }
                return false;
            }
        }
        Object actual = extractUserScalarValue(u, stripped);
        if (actual == null) {
            return "ne".equals(op);
        }
        boolean caseExact = !ScimFilterParser.isCaseInsensitiveAttribute(stripped);
        if ("meta.resourcetype".equals(stripped)) {
            caseExact = false;
        }
        return compareAttributeValue(stripped, actual, op, target, caseExact);
    }

    private static Object extractUserScalarValue(ScimUser u, String lower) {
        if (lower.startsWith("name.")) {
            return switch (lower.substring(5)) {
                case "formatted" -> u.getNameFormatted();
                case "familyname" -> u.getNameFamilyName();
                case "givenname" -> u.getNameGivenName();
                case "middlename" -> u.getNameMiddleName();
                case "honorificprefix" -> u.getNameHonorificPrefix();
                case "honorificsuffix" -> u.getNameHonorificSuffix();
                default -> null;
            };
        }
        if (lower.startsWith("meta.")) {
            return switch (lower.substring(5)) {
                case "resourcetype" -> "User";
                case "created" -> u.getCreatedAt();
                case "lastmodified" -> (u.getVersion() == null || u.getVersion() == 0L) ? u.getCreatedAt() : u.getLastModified();
                case "version" -> "W/\"" + (u.getVersion() != null ? u.getVersion() : 0L) + "\"";
                case "location" -> u.getId() != null ? "/Users/" + u.getId() : null;
                default -> null;
            };
        }
        if (lower.startsWith(ScimFilterParser.ENTERPRISE_URN_PREFIX)) {
            return switch (lower.substring(ScimFilterParser.ENTERPRISE_URN_PREFIX.length())) {
                case "employeenumber" -> u.getEnterpriseEmployeeNumber();
                case "costcenter" -> u.getEnterpriseCostCenter();
                case "organization" -> u.getEnterpriseOrganization();
                case "division" -> u.getEnterpriseDivision();
                case "department" -> u.getEnterpriseDepartment();
                case "manager", "manager.value" -> u.getEnterpriseManagerValue();
                case "manager.$ref" -> (u.getEnterpriseManagerRef() != null && !u.getEnterpriseManagerRef().isBlank())
                        ? u.getEnterpriseManagerRef()
                        : (u.getEnterpriseManagerValue() != null ? "/Users/" + u.getEnterpriseManagerValue() : null);
                case "manager.displayname" -> u.getEnterpriseManagerDisplay();
                default -> null;
            };
        }
        return switch (lower) {
            case "id" -> u.getId();
            case "username" -> u.getUserName();
            case "externalid" -> u.getExternalId();
            case "displayname" -> u.getDisplayName();
            case "nickname" -> u.getNickName();
            case "profileurl" -> u.getProfileUrl();
            case "title" -> u.getTitle();
            case "usertype" -> u.getUserType();
            case "preferredlanguage" -> u.getPreferredLanguage();
            case "locale" -> u.getLocale();
            case "timezone" -> u.getTimezone();
            case "active" -> u.isActive();
            case "schemas" -> "urn:ietf:params:scim:schemas:core:2.0:User";
            default -> null;
        };
    }

    private static boolean evalGroupPresence(ScimGroup g, String rawAttr) {
        if (ScimFilterParser.isOtherResourceAttribute(rawAttr, false)) {
            return false;
        }
        String stripped = ScimFilterParser.stripCoreUrnPrefix(rawAttr, false).toLowerCase(Locale.ROOT);
        if ("members".equals(stripped)) {
            return g.getMembers() != null && !g.getMembers().isEmpty();
        }
        if ("meta".equals(stripped) || "schemas".equals(stripped)) {
            return true;
        }
        if (stripped.startsWith("members.")) {
            if (g.getMembers() == null) return false;
            String sub = stripped.substring(8);
            for (ScimGroupMembership m : g.getMembers()) {
                if (lookupElementValue(memberToEvalMap(m), sub) != null) return true;
            }
            return false;
        }
        return extractGroupScalarValue(g, stripped) != null;
    }

    private static boolean evalGroupComparison(ScimGroup g, String rawAttr, String op, String target) {
        if (ScimFilterParser.isOtherResourceAttribute(rawAttr, false)) {
            return false;
        }
        String stripped = ScimFilterParser.stripCoreUrnPrefix(rawAttr, false).toLowerCase(Locale.ROOT);
        if ("members".equals(stripped)) {
            stripped = "members.value";
        }
        if (stripped.startsWith("members.")) {
            String sub = stripped.substring(8);
            List<ScimGroupMembership> members = g.getMembers() != null ? g.getMembers() : Collections.emptyList();
            boolean caseExact = "$ref".equals(sub);
            if ("ne".equals(op)) {
                for (ScimGroupMembership m : members) {
                    Object v = lookupElementValue(memberToEvalMap(m), sub);
                    if (v != null && compareAttributeValue(sub, v, "eq", target, caseExact)) return false;
                }
                return true;
            }
            for (ScimGroupMembership m : members) {
                Object v = lookupElementValue(memberToEvalMap(m), sub);
                if (v != null && compareAttributeValue(sub, v, op, target, caseExact)) return true;
            }
            return false;
        }
        Object actual = extractGroupScalarValue(g, stripped);
        if (actual == null) {
            return "ne".equals(op);
        }
        boolean caseExact = !ScimFilterParser.isCaseInsensitiveAttribute(stripped);
        if ("meta.resourcetype".equals(stripped)) {
            caseExact = false;
        }
        return compareAttributeValue(stripped, actual, op, target, caseExact);
    }

    private static Object extractGroupScalarValue(ScimGroup g, String lower) {
        if (lower.startsWith("meta.")) {
            return switch (lower.substring(5)) {
                case "resourcetype" -> "Group";
                case "created" -> g.getCreatedAt();
                case "lastmodified" -> (g.getVersion() == null || g.getVersion() == 0L) ? g.getCreatedAt() : g.getLastModified();
                case "version" -> "W/\"" + (g.getVersion() != null ? g.getVersion() : 0L) + "\"";
                case "location" -> g.getId() != null ? "/Groups/" + g.getId() : null;
                default -> null;
            };
        }
        return switch (lower) {
            case "id" -> g.getId();
            case "displayname" -> g.getDisplayName();
            case "externalid" -> g.getExternalId();
            case "schemas" -> "urn:ietf:params:scim:schemas:core:2.0:Group";
            default -> null;
        };
    }

    private static boolean compareAttributeValue(String attrName, Object actual, String op, String target, boolean caseExact) {
        if (attrName != null && ("$ref".equalsIgnoreCase(attrName) || attrName.toLowerCase(Locale.ROOT).endsWith(".$ref"))) {
            if ("eq".equals(op)) {
                return compareSingleValue(actual, "eq", target, caseExact)
                        || ScimCanonicalizer.scimRefsComparable(actual.toString(), target);
            }
            if ("ne".equals(op)) {
                return !compareSingleValue(actual, "eq", target, caseExact)
                        && !ScimCanonicalizer.scimRefsComparable(actual.toString(), target);
            }
        }
        return compareSingleValue(actual, op, target, caseExact);
    }

    private static boolean compareSingleValue(Object actual, String op, String target, boolean caseExact) {
        if (actual instanceof Boolean b) {
            boolean targetBool = Boolean.parseBoolean(target);
            return switch (op) {
                case "eq" -> b == targetBool;
                case "ne" -> b != targetBool;
                default -> false;
            };
        }
        if (actual instanceof Instant inst) {
            Instant targetInst = ScimFilterParser.parseDateTime(target);
            if (targetInst == null) return false;
            return switch (op) {
                case "eq" -> inst.equals(targetInst);
                case "ne" -> !inst.equals(targetInst);
                case "gt" -> inst.isAfter(targetInst);
                case "ge" -> !inst.isBefore(targetInst);
                case "lt" -> inst.isBefore(targetInst);
                case "le" -> !inst.isAfter(targetInst);
                default -> false;
            };
        }
        if (actual instanceof UUID uuid) {
            try {
                UUID targetUuid = UUID.fromString(target);
                return switch (op) {
                    case "eq" -> uuid.equals(targetUuid);
                    case "ne" -> !uuid.equals(targetUuid);
                    default -> false;
                };
            } catch (IllegalArgumentException e) {
                return "ne".equals(op);
            }
        }
        String s = ScimCanonicalizer.normalizeNfc(actual.toString());
        String a = caseExact ? s : s.toLowerCase(Locale.ROOT);
        String t = caseExact ? target : target.toLowerCase(Locale.ROOT);
        return switch (op) {
            case "eq" -> a.equals(t);
            case "ne" -> !a.equals(t);
            case "co" -> a.contains(t);
            case "sw" -> a.startsWith(t);
            case "ew" -> a.endsWith(t);
            case "gt" -> a.compareTo(t) > 0;
            case "ge" -> a.compareTo(t) >= 0;
            case "lt" -> a.compareTo(t) < 0;
            case "le" -> a.compareTo(t) <= 0;
            default -> false;
        };
    }
}
