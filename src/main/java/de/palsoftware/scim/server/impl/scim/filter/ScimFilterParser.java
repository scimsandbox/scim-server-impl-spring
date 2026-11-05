package de.palsoftware.scim.server.impl.scim.filter;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;
import jakarta.persistence.criteria.*;
import org.hibernate.query.criteria.JpaExpression;
import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses SCIM filter expressions (RFC 7644 §3.4.2.2) into JPA Specifications and FilterNode ASTs.
 * Supports: eq, ne, co, sw, ew, pr, gt, ge, lt, le, and, or, not, grouping (), and valuePath [].
 */
public class ScimFilterParser {

    private ScimFilterParser() {
    }

    public sealed interface FilterNode permits
            FilterNode.AndNode,
            FilterNode.OrNode,
            FilterNode.NotNode,
            FilterNode.ComparisonNode,
            FilterNode.PresenceNode,
            FilterNode.ValuePathNode {
        record AndNode(FilterNode left, FilterNode right) implements FilterNode {}
        record OrNode(FilterNode left, FilterNode right) implements FilterNode {}
        record NotNode(FilterNode inner) implements FilterNode {}
        record ComparisonNode(String attrPath, String operator, String value, boolean quoted) implements FilterNode {}
        record PresenceNode(String attrPath) implements FilterNode {}
        record ValuePathNode(String parentAttr, FilterNode inner) implements FilterNode {}
    }

    private static final String ATTR_WORKSPACE = "workspace";
    private static final String META_ATTR_CREATED = "created";
    private static final String ATTR_CREATED_AT = "createdAt";
    private static final String ATTR_LAST_MODIFIED = "lastModified";
    private static final String ATTR_NICK_NAME = "nickName";
    private static final String ATTR_USER_TYPE = "userType";
    private static final String ATTR_PREFERRED_LANGUAGE = "preferredLanguage";
    private static final String ATTR_LOCALE = "locale";
    private static final String ATTR_TIMEZONE = "timezone";
    private static final String ATTR_USER_NAME = "userName";
    private static final String ATTR_DISPLAY_NAME = "displayName";
    private static final String ATTR_EXTERNAL_ID = "externalId";
    private static final String ATTR_ID = "id";
    private static final String ATTR_TITLE = "title";
    private static final String ATTR_DISPLAY_NAME_LOWER = "displayname";
    private static final String BOOLEAN_FALSE = "false";

    static final String CORE_USER_URN_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:user:";
    static final String CORE_GROUP_URN_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:group:";
    static final String ENTERPRISE_URN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user";
    static final String ENTERPRISE_URN_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:";

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\(|\\)|\\[|\\]|" +
            "\"(?:[^\"\\\\]|\\\\.)*+\"|" +
            "\\b(?:true|false|null)\\b|" +
            "\\b(?:and|or|not)\\b|" +
            "\\b(?:eq|ne|co|sw|ew|pr|gt|ge|lt|le)\\b|" +
            "[\\w.$:-]+",
            Pattern.CASE_INSENSITIVE
    );

    static final Set<String> JSON_COLLECTIONS = Set.of(
            "emails", "phonenumbers", "addresses", "entitlements", "roles", "ims", "photos", "x509certificates"
    );

    private static final Set<String> VALID_OPERATORS = Set.of(
            "eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"
    );

    // Valid User-only attributes (unprefixed lowercase) for cross-resource absence detection on Group
    private static final Set<String> KNOWN_USER_ONLY_ATTRIBUTES = Set.of(
            "username", "nickname", "profileurl", "title", "usertype",
            "preferredlanguage", "locale", "timezone", "active", "password",
            "name", "name.formatted", "name.familyname", "name.givenname",
            "name.middlename", "name.honorificprefix", "name.honorificsuffix",
            "emails", "emails.value", "emails.type", "emails.primary", "emails.display",
            "phonenumbers", "phonenumbers.value", "phonenumbers.type", "phonenumbers.primary", "phonenumbers.display",
            "ims", "ims.value", "ims.type", "ims.primary", "ims.display",
            "photos", "photos.value", "photos.type", "photos.primary", "photos.display",
            "addresses", "addresses.formatted", "addresses.streetaddress", "addresses.locality",
            "addresses.region", "addresses.postalcode", "addresses.country", "addresses.type", "addresses.primary",
            "entitlements", "entitlements.value", "entitlements.type", "entitlements.primary", "entitlements.display",
            "roles", "roles.value", "roles.type", "roles.primary", "roles.display",
            "x509certificates", "x509certificates.value", "x509certificates.type", "x509certificates.primary", "x509certificates.display",
            "groups", "groups.value", "groups.$ref", "groups.display", "groups.type"
    );

    private static final Set<String> KNOWN_ENTERPRISE_SUB_ATTRIBUTES = Set.of(
            "employeenumber", "costcenter", "organization", "division", "department",
            "manager", "manager.value", "manager.$ref", "manager.displayname"
    );

    // Valid Group-only attributes (unprefixed lowercase) for cross-resource absence detection on User
    private static final Set<String> KNOWN_GROUP_ONLY_ATTRIBUTES = Set.of(
            "members", "members.value", "members.$ref", "members.type", "members.display"
    );

    private static final Set<String> KNOWN_COMMON_ATTRIBUTES = Set.of(
            "id", "externalid", "schemas", "displayname",
            "meta", "meta.resourcetype", "meta.created", "meta.lastmodified", "meta.location", "meta.version"
    );

    public static boolean containsValuePath(String filter) {
        if (filter == null || filter.isBlank()) {
            return false;
        }
        boolean inQuotes = false;
        for (int i = 0; i < filter.length(); i++) {
            char c = filter.charAt(i);
            if (c == '\\' && inQuotes && i + 1 < filter.length()) {
                i++;
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes && c == '[') {
                return true;
            }
        }
        return false;
    }

    public static FilterNode parseAst(String filter, boolean isUser) {
        if (filter == null || filter.isBlank()) {
            return null;
        }
        List<String> tokens = tokenize(filter);
        int[] pos = {0};
        FilterNode node = parseAstOr(tokens, pos);
        if (pos[0] < tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Unexpected tokens at end of filter: " + tokens.get(pos[0]));
        }
        ScimFilterEvaluator.validateAst(node, isUser, null);
        return node;
    }

    public static boolean astReferencesGroups(FilterNode node) {
        if (node == null) return false;
        return switch (node) {
            case FilterNode.AndNode n -> astReferencesGroups(n.left()) || astReferencesGroups(n.right());
            case FilterNode.OrNode n -> astReferencesGroups(n.left()) || astReferencesGroups(n.right());
            case FilterNode.NotNode n -> astReferencesGroups(n.inner());
            case FilterNode.ValuePathNode n -> {
                String s = stripCoreUrnPrefix(n.parentAttr(), true).toLowerCase(Locale.ROOT);
                yield "groups".equals(s);
            }
            case FilterNode.PresenceNode n -> {
                String s = stripCoreUrnPrefix(n.attrPath(), true).toLowerCase(Locale.ROOT);
                yield "groups".equals(s) || s.startsWith("groups.");
            }
            case FilterNode.ComparisonNode n -> {
                String s = stripCoreUrnPrefix(n.attrPath(), true).toLowerCase(Locale.ROOT);
                yield "groups".equals(s) || s.startsWith("groups.");
            }
        };
    }

    private static FilterNode parseAstOr(List<String> tokens, int[] pos) {
        FilterNode left = parseAstAnd(tokens, pos);
        while (pos[0] < tokens.size() && "or".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            FilterNode right = parseAstAnd(tokens, pos);
            left = new FilterNode.OrNode(left, right);
        }
        return left;
    }

    private static FilterNode parseAstAnd(List<String> tokens, int[] pos) {
        FilterNode left = parseAstNot(tokens, pos);
        while (pos[0] < tokens.size() && "and".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            FilterNode right = parseAstNot(tokens, pos);
            left = new FilterNode.AndNode(left, right);
        }
        return left;
    }

    private static FilterNode parseAstNot(List<String> tokens, int[] pos) {
        if (pos[0] < tokens.size() && "not".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            return new FilterNode.NotNode(parseAstAtom(tokens, pos));
        }
        return parseAstAtom(tokens, pos);
    }

    private static FilterNode parseAstAtom(List<String> tokens, int[] pos) {
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Unexpected end of filter expression");
        }
        String token = tokens.get(pos[0]);
        if ("(".equals(token)) {
            pos[0]++;
            FilterNode inner = parseAstOr(tokens, pos);
            if (pos[0] >= tokens.size() || !")".equals(tokens.get(pos[0]))) {
                throw new ScimException(400, "invalidFilter", "Missing closing parenthesis");
            }
            pos[0]++;
            return inner;
        }
        if (")".equals(token) || "[".equals(token) || "]".equals(token)) {
            throw new ScimException(400, "invalidFilter", "Unexpected token in filter: " + token);
        }

        String attrPath = token;
        pos[0]++;

        if (pos[0] < tokens.size() && "[".equals(tokens.get(pos[0]))) {
            pos[0]++; // consume [
            FilterNode inner = parseAstOr(tokens, pos);
            if (pos[0] >= tokens.size() || !"]".equals(tokens.get(pos[0]))) {
                throw new ScimException(400, "invalidFilter", "Missing closing bracket for value path filter");
            }
            pos[0]++; // consume ]
            // Optional trailing sub-attribute after ']', e.g. emails[type eq "work"].value eq "x"
            if (pos[0] < tokens.size() && tokens.get(pos[0]).startsWith(".")) {
                String subSuffix = tokens.get(pos[0]).substring(1);
                pos[0]++;
                if (pos[0] >= tokens.size()) {
                    throw new ScimException(400, "invalidFilter", "Incomplete filter after value path");
                }
                String op = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
                pos[0]++;
                FilterNode tailNode = buildLeafAstNode(subSuffix, op, tokens, pos);
                return new FilterNode.ValuePathNode(attrPath, new FilterNode.AndNode(inner, tailNode));
            }
            return new FilterNode.ValuePathNode(attrPath, inner);
        }

        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Incomplete filter expression after: " + attrPath);
        }
        String op = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;
        return buildLeafAstNode(attrPath, op, tokens, pos);
    }

    private static final Pattern UNQUOTED_NUMBER_LITERAL =
            Pattern.compile("^-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?$");

    private static FilterNode buildLeafAstNode(String attrPath, String op, List<String> tokens, int[] pos) {
        if ("pr".equals(op)) {
            return new FilterNode.PresenceNode(attrPath);
        }
        if (!VALID_OPERATORS.contains(op)) {
            throw new ScimException(400, "invalidFilter", "Unknown filter operator: " + op);
        }
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + op);
        }
        String rawValue = tokens.get(pos[0]);
        if ("(".equals(rawValue) || ")".equals(rawValue) || "[".equals(rawValue) || "]".equals(rawValue)) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + op);
        }
        pos[0]++;
        boolean quoted = rawValue.startsWith("\"") && rawValue.endsWith("\"") && rawValue.length() >= 2;
        if (!quoted && !isUnquotedCompValueLiteral(rawValue)) {
            throw new ScimException(400, "invalidFilter",
                    "Filter string value must be enclosed in double quotes: " + rawValue);
        }
        String value = quoted ? unquote(rawValue) : rawValue;
        return new FilterNode.ComparisonNode(attrPath, op, value, quoted);
    }

    private static boolean isUnquotedCompValueLiteral(String rawValue) {
        return "true".equalsIgnoreCase(rawValue)
                || "false".equalsIgnoreCase(rawValue)
                || "null".equalsIgnoreCase(rawValue)
                || UNQUOTED_NUMBER_LITERAL.matcher(rawValue).matches();
    }

    // ── USER FILTER (JPA SPECIFICATION) ──────────────────

    public static Specification<ScimUser> parseUserFilter(String filter, UUID workspaceId) {
        if (filter == null || filter.isBlank()) {
            return (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
        }
        try {
            List<String> tokens = tokenize(filter);
            int[] pos = {0};
            Specification<ScimUser> spec = parseOrExpression(tokens, pos, true, null, workspaceId);
            if (pos[0] < tokens.size()) {
                throw new ScimException(400, "invalidFilter", "Unexpected tokens at end of filter: " + tokens.get(pos[0]));
            }
            Specification<ScimUser> wsSpec = (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
            return wsSpec.and(spec);
        } catch (ScimException e) {
            throw e;
        } catch (Exception e) {
            throw new ScimException(400, "invalidFilter", "Invalid filter expression: " + e.getMessage(), e);
        }
    }

    // ── GROUP FILTER (JPA SPECIFICATION) ─────────────────

    public static Specification<ScimGroup> parseGroupFilter(String filter, UUID workspaceId) {
        if (filter == null || filter.isBlank()) {
            return (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
        }
        try {
            List<String> tokens = tokenize(filter);
            int[] pos = {0};
            Specification<ScimGroup> spec = parseOrExpression(tokens, pos, false, null, workspaceId);
            if (pos[0] < tokens.size()) {
                throw new ScimException(400, "invalidFilter", "Unexpected tokens at end of filter: " + tokens.get(pos[0]));
            }
            Specification<ScimGroup> wsSpec = (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
            return wsSpec.and(spec);
        } catch (ScimException e) {
            throw e;
        } catch (Exception e) {
            throw new ScimException(400, "invalidFilter", "Invalid filter expression: " + e.getMessage(), e);
        }
    }

    // ── RECURSIVE DESCENT PARSER (JPA SPECIFICATION) ─────

    private static <T> Specification<T> parseOrExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath, UUID workspaceId) {
        Specification<T> left = parseAndExpression(tokens, pos, isUser, parentPath, workspaceId);
        while (pos[0] < tokens.size() && "or".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> right = parseAndExpression(tokens, pos, isUser, parentPath, workspaceId);
            left = left.or(right);
        }
        return left;
    }

    private static <T> Specification<T> parseAndExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath, UUID workspaceId) {
        Specification<T> left = parseNotExpression(tokens, pos, isUser, parentPath, workspaceId);
        while (pos[0] < tokens.size() && "and".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> right = parseNotExpression(tokens, pos, isUser, parentPath, workspaceId);
            left = left.and(right);
        }
        return left;
    }

    private static <T> Specification<T> parseNotExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath, UUID workspaceId) {
        if (pos[0] < tokens.size() && "not".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> inner = parseAtom(tokens, pos, isUser, parentPath, workspaceId);
            return Specification.not(inner);
        }
        return parseAtom(tokens, pos, isUser, parentPath, workspaceId);
    }

    static String stripCoreUrnPrefix(String attrPath, boolean isUser) {
        String lower = attrPath.toLowerCase(Locale.ROOT);
        if (isUser && lower.startsWith(CORE_USER_URN_PREFIX)) {
            return attrPath.substring(CORE_USER_URN_PREFIX.length());
        }
        if (!isUser && lower.startsWith(CORE_GROUP_URN_PREFIX)) {
            return attrPath.substring(CORE_GROUP_URN_PREFIX.length());
        }
        return attrPath;
    }

    static boolean isOtherResourceAttribute(String rawAttrPath, boolean isUser) {
        String lower = rawAttrPath.toLowerCase(Locale.ROOT);
        if (isUser) {
            if (lower.startsWith(CORE_GROUP_URN_PREFIX)) {
                String sub = lower.substring(CORE_GROUP_URN_PREFIX.length());
                return KNOWN_GROUP_ONLY_ATTRIBUTES.contains(sub) || KNOWN_COMMON_ATTRIBUTES.contains(sub);
            }
            return KNOWN_GROUP_ONLY_ATTRIBUTES.contains(lower);
        } else {
            if (lower.startsWith(CORE_USER_URN_PREFIX)) {
                String sub = lower.substring(CORE_USER_URN_PREFIX.length());
                return KNOWN_USER_ONLY_ATTRIBUTES.contains(sub) || KNOWN_COMMON_ATTRIBUTES.contains(sub);
            }
            if (lower.equals(ENTERPRISE_URN)) {
                return true;
            }
            if (lower.startsWith(ENTERPRISE_URN_PREFIX)) {
                String sub = lower.substring(ENTERPRISE_URN_PREFIX.length());
                return KNOWN_ENTERPRISE_SUB_ATTRIBUTES.contains(sub);
            }
            return KNOWN_USER_ONLY_ATTRIBUTES.contains(lower);
        }
    }

    private static String escapeLikeValue(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    static String unquote(String rawValue) {
        if (rawValue == null) return null;
        if (rawValue.length() >= 2 && rawValue.startsWith("\"") && rawValue.endsWith("\"")) {
            String inner = rawValue.substring(1, rawValue.length() - 1);
            StringBuilder sb = new StringBuilder(inner.length());
            for (int i = 0; i < inner.length(); i++) {
                char c = inner.charAt(i);
                if (c == '\\' && i + 1 < inner.length()) {
                    char next = inner.charAt(++i);
                    switch (next) {
                        case '"', '\\', '/' -> sb.append(next);
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (i + 4 < inner.length()) {
                                String hex = inner.substring(i + 1, i + 5);
                                try {
                                    sb.append((char) Integer.parseInt(hex, 16));
                                    i += 4;
                                } catch (NumberFormatException e) {
                                    sb.append("\\u");
                                }
                            } else {
                                sb.append("\\u");
                            }
                        }
                        default -> sb.append(next);
                    }
                } else {
                    sb.append(c);
                }
            }
            return ScimCanonicalizer.normalizeNfc(sb.toString());
        }
        return ScimCanonicalizer.normalizeNfc(rawValue);
    }

    private static <T> Specification<T> parseAtom(List<String> tokens, int[] pos, boolean isUser, String parentPath, UUID workspaceId) {
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Unexpected end of filter expression");
        }

        String token = tokens.get(pos[0]);

        if ("(".equals(token)) {
            pos[0]++;
            Specification<T> inner = parseOrExpression(tokens, pos, isUser, parentPath, workspaceId);
            if (pos[0] >= tokens.size() || !")".equals(tokens.get(pos[0]))) {
                throw new ScimException(400, "invalidFilter", "Missing closing parenthesis");
            }
            pos[0]++;
            return inner;
        }

        String rawTokenAttr = token;
        pos[0]++;

        if (pos[0] < tokens.size() && "[".equals(tokens.get(pos[0]))) {
            return parseValuePathBranch(tokens, pos, rawTokenAttr, isUser, workspaceId);
        }

        String combinedPath = parentPath != null ? parentPath + "." + rawTokenAttr : rawTokenAttr;
        String attrPath = stripCoreUrnPrefix(combinedPath, isUser);

        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Incomplete filter expression after: " + attrPath);
        }

        // Cross-resource attribute absence check (RFC 7644 §3.4.2.1 & §3.4.2.2)
        if (isOtherResourceAttribute(combinedPath, isUser)) {
            return consumeOperatorAndReturnUnassigned(tokens, pos, combinedPath);
        }

        // Handle JSON collections on User (e.g. emails.value eq "test" or shorthand emails eq "test")
        if (isUser && attrPath.contains(".")) {
            String[] parts = attrPath.split("\\.", 2);
            if (JSON_COLLECTIONS.contains(parts[0].toLowerCase(Locale.ROOT))) {
                return handleJsonCollectionFilter(tokens, pos, parts[0], parts[1], attrPath);
            }
            if ("groups".equalsIgnoreCase(parts[0])) {
                return handleUserGroupsSubFilter(tokens, pos, parts[1], attrPath, workspaceId);
            }
        }
        if (isUser && !"pr".equalsIgnoreCase(tokens.get(pos[0]))) {
            String attrLower = attrPath.toLowerCase(Locale.ROOT);
            if (JSON_COLLECTIONS.contains(attrLower) && !"addresses".equals(attrLower)) {
                return handleJsonCollectionFilter(tokens, pos, attrPath, "value", attrPath + ".value");
            }
            if ("groups".equals(attrLower)) {
                return handleUserGroupsSubFilter(tokens, pos, "value", attrPath + ".value", workspaceId);
            }
        }

        // Handle Group members.<subAttr> or shorthand members <op> <val> (RFC 7644 §3.4.2.2)
        if (!isUser && attrPath.toLowerCase(Locale.ROOT).startsWith("members.")) {
            String sub = attrPath.substring("members.".length());
            return handleGroupMembersSubFilter(tokens, pos, sub, attrPath);
        }
        if (!isUser && "members".equalsIgnoreCase(attrPath) && !"pr".equalsIgnoreCase(tokens.get(pos[0]))) {
            return handleGroupMembersSubFilter(tokens, pos, "value", "members.value");
        }

        return parseOperatorAndValue(tokens, pos, attrPath, isUser, workspaceId);
    }

    private static <T> Specification<T> consumeOperatorAndReturnUnassigned(List<String> tokens, int[] pos, String attrPath) {
        String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;
        if (!"pr".equals(operator)) {
            if (!VALID_OPERATORS.contains(operator)) {
                return (root, query, cb) -> {
                    throw new ScimException(400, "invalidFilter", "Unknown filter operator: " + operator);
                };
            }
            if (pos[0] >= tokens.size()) {
                throw new ScimException(400, "invalidFilter", "Missing value for operator: " + operator);
            }
            pos[0]++; // consume value token
        }
        return (root, query, cb) -> falsePredicate(cb);
    }

    private static <T> Specification<T> parseOperatorAndValue(List<String> tokens, int[] pos, String attrPath, boolean isUser, UUID workspaceId) {
        String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;

        // Presence operator (no value)
        if ("pr".equals(operator)) {
            String stripped = stripCoreUrnPrefix(attrPath, isUser).toLowerCase(Locale.ROOT);
            if ("meta".equals(stripped) || "meta.resourcetype".equals(stripped)
                    || "meta.version".equals(stripped) || "meta.location".equals(stripped)
                    || "schemas".equals(stripped)) {
                return (root, query, cb) -> truePredicate(cb);
            }
            if (isUser) {
                if (JSON_COLLECTIONS.contains(stripped)) {
                    return (root, query, cb) -> {
                        String col = getCollectionFieldName(stripped);
                        Expression<String> jsonStr = castToString(root.get(col));
                        Predicate nonNull = cb.isNotNull(root.get(col));
                        Predicate notEmptyArr = cb.notEqual(jsonStr, "[]");
                        Predicate notJsonNull = cb.notEqual(jsonStr, "null");
                        return cb.and(cb.and(nonNull, notEmptyArr), notJsonNull);
                    };
                }
                if ("groups".equals(stripped)) {
                    return (root, query, cb) -> buildUserGroupsExistsPredicate(root, query, cb, workspaceId, null, null, null);
                }
                if ("name".equals(stripped)) {
                    return (root, query, cb) -> orAll(cb,
                            cb.isNotNull(root.get("nameFormatted")),
                            cb.isNotNull(root.get("nameFamilyName")),
                            cb.isNotNull(root.get("nameGivenName")),
                            cb.isNotNull(root.get("nameMiddleName")),
                            cb.isNotNull(root.get("nameHonorificPrefix")),
                            cb.isNotNull(root.get("nameHonorificSuffix")));
                }
                if (ENTERPRISE_URN.equals(stripped)) {
                    return (root, query, cb) -> orAll(cb,
                            cb.isNotNull(root.get("enterpriseEmployeeNumber")),
                            cb.isNotNull(root.get("enterpriseCostCenter")),
                            cb.isNotNull(root.get("enterpriseOrganization")),
                            cb.isNotNull(root.get("enterpriseDivision")),
                            cb.isNotNull(root.get("enterpriseDepartment")),
                            cb.isNotNull(root.get("enterpriseManagerValue")));
                }
                if ((ENTERPRISE_URN_PREFIX + "manager").equals(stripped)
                        || (ENTERPRISE_URN_PREFIX + "manager.$ref").equals(stripped)) {
                    return (root, query, cb) -> orAll(cb,
                            cb.isNotNull(root.get("enterpriseManagerValue")),
                            cb.isNotNull(root.get("enterpriseManagerRef")));
                }
            } else {
                if ("members".equals(stripped)) {
                    return (root, query, cb) -> buildGroupMembersExistsPredicate(root, query, cb, null, null, null);
                }
            }
            return (root, query, cb) -> {
                Path<?> path = resolveAttributePath(root, attrPath, isUser);
                return cb.isNotNull(path);
            };
        }

        // Comparison operators need a value
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + operator);
        }

        String rawValue = tokens.get(pos[0]);
        pos[0]++;

        final String finalValue = unquote(rawValue);

        String stripped = stripCoreUrnPrefix(attrPath, isUser).toLowerCase(Locale.ROOT);
        if ("meta.resourcetype".equals(stripped)) {
            return (root, query, cb) -> {
                String myType = isUser ? "User" : "Group";
                boolean match;
                switch (operator) {
                    case "eq" -> {
                        match = myType.equalsIgnoreCase(finalValue);
                        return match ? truePredicate(cb) : falsePredicate(cb);
                    }
                    case "ne" -> {
                        match = myType.equalsIgnoreCase(finalValue);
                        return match ? falsePredicate(cb) : truePredicate(cb);
                    }
                    case "co" -> {
                        match = myType.toLowerCase(Locale.ROOT).contains(finalValue.toLowerCase(Locale.ROOT));
                        return match ? truePredicate(cb) : falsePredicate(cb);
                    }
                    case "sw" -> {
                        match = myType.toLowerCase(Locale.ROOT).startsWith(finalValue.toLowerCase(Locale.ROOT));
                        return match ? truePredicate(cb) : falsePredicate(cb);
                    }
                    case "ew" -> {
                        match = myType.toLowerCase(Locale.ROOT).endsWith(finalValue.toLowerCase(Locale.ROOT));
                        return match ? truePredicate(cb) : falsePredicate(cb);
                    }
                    default -> throw new ScimException(400, "invalidFilter",
                            "Operator '" + operator + "' is not supported for meta.resourceType");
                }
            };
        }

        return (root, query, cb) -> {
            Path<?> path = resolveAttributePath(root, attrPath, isUser);
            return buildComparisonPredicate(cb, path, operator, finalValue, attrPath);
        };
    }

    private static <T> Specification<T> parseValuePathBranch(List<String> tokens, int[] pos, String attrPath, boolean isUser, UUID workspaceId) {
        pos[0]++; // consume [
        String normalizedParent = stripCoreUrnPrefix(attrPath, isUser);
        Specification<T> inner = parseOrExpression(tokens, pos, isUser, normalizedParent, workspaceId);
        if (pos[0] >= tokens.size() || !"]".equals(tokens.get(pos[0]))) {
            throw new ScimException(400, "invalidFilter", "Missing closing bracket for value path filter");
        }
        pos[0]++; // consume ]
        return inner;
    }

    private static <T> Specification<T> handleUserGroupsSubFilter(List<String> tokens, int[] pos, String subAttr, String attrPath, UUID workspaceId) {
        String subLower = subAttr.toLowerCase(Locale.ROOT);
        if (!Set.of("value", "display", "$ref", "type").contains(subLower)) {
            String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
            pos[0]++;
            if (!"pr".equals(operator) && pos[0] < tokens.size()) {
                pos[0]++;
            }
            return (root, query, cb) -> {
                throw new ScimException(400, "invalidFilter", "Unknown groups sub-attribute: " + subAttr);
            };
        }
        String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;
        if ("pr".equals(operator)) {
            return (root, query, cb) -> buildUserGroupsExistsPredicate(root, query, cb, workspaceId, subLower, "pr", null);
        }
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + operator);
        }
        String val = unquote(tokens.get(pos[0]));
        pos[0]++;
        return (root, query, cb) -> buildUserGroupsExistsPredicate(root, query, cb, workspaceId, subLower, operator, val);
    }

    private static Predicate buildUserGroupsExistsPredicate(Root<?> root, CriteriaQuery<?> query, CriteriaBuilder cb,
                                                             UUID workspaceId, String subLower, String op, String val) {
        Subquery<UUID> sq = query != null ? query.subquery(UUID.class) : null;
        if (sq == null) {
            return cb.isNotNull(root.get(ATTR_ID));
        }
        Root<ScimGroupMembership> mRoot = sq.from(ScimGroupMembership.class);
        sq.select(mRoot.get("memberValue"));
        Predicate base = cb.and(
                cb.equal(mRoot.get("memberValue"), root.get(ATTR_ID)),
                cb.equal(mRoot.get("group").get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId));
        if (subLower != null && op != null && !"pr".equals(op)) {
            if ("type".equals(subLower)) {
                boolean matchesDirect = "direct".equalsIgnoreCase(val);
                if ("eq".equals(op) && !matchesDirect) return falsePredicate(cb);
                if ("ne".equals(op) && matchesDirect) return falsePredicate(cb);
            } else if ("value".equals(subLower)) {
                try {
                    UUID gid = UUID.fromString(val);
                    Predicate cmp = "ne".equals(op)
                            ? cb.notEqual(mRoot.get("group").get(ATTR_ID), gid)
                            : cb.equal(mRoot.get("group").get(ATTR_ID), gid);
                    base = cb.and(base, cmp);
                } catch (IllegalArgumentException e) {
                    throw new ScimException(400, "invalidFilter", "Invalid UUID for groups.value: " + val, e);
                }
            } else if ("display".equals(subLower)) {
                Predicate cmp = buildComparisonPredicate(cb, mRoot.get("group").get(ATTR_DISPLAY_NAME), op, val, ATTR_DISPLAY_NAME);
                base = cb.and(base, cmp);
            } else if ("$ref".equals(subLower)) {
                String tail = ScimCanonicalizer.extractCanonicalScimResourceTail(val);
                if (tail != null && tail.startsWith("Groups/")) {
                    try {
                        UUID gid = UUID.fromString(tail.substring("Groups/".length()));
                        Predicate cmp = "ne".equals(op)
                                ? cb.notEqual(mRoot.get("group").get(ATTR_ID), gid)
                                : cb.equal(mRoot.get("group").get(ATTR_ID), gid);
                        base = cb.and(base, cmp);
                    } catch (IllegalArgumentException e) {
                        if ("eq".equals(op)) return falsePredicate(cb);
                    }
                } else if ("eq".equals(op)) {
                    return falsePredicate(cb);
                }
            }
        }
        sq.where(base);
        return cb.exists(sq);
    }

    private static <T> Specification<T> handleGroupMembersSubFilter(List<String> tokens, int[] pos, String subAttr, String attrPath) {
        String subLower = subAttr.toLowerCase(Locale.ROOT);
        if (!Set.of("value", "display", "$ref", "type").contains(subLower)) {
            String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
            pos[0]++;
            if (!"pr".equals(operator) && pos[0] < tokens.size()) {
                pos[0]++;
            }
            return (root, query, cb) -> {
                throw new ScimException(400, "invalidFilter", "Unknown members sub-attribute: " + subAttr);
            };
        }
        String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;
        if ("pr".equals(operator)) {
            return (root, query, cb) -> buildGroupMembersExistsPredicate(root, query, cb, subLower, "pr", null);
        }
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + operator);
        }
        String val = unquote(tokens.get(pos[0]));
        pos[0]++;
        return (root, query, cb) -> buildGroupMembersExistsPredicate(root, query, cb, subLower, operator, val);
    }

    private static Predicate buildGroupMembersExistsPredicate(Root<?> root, CriteriaQuery<?> query, CriteriaBuilder cb,
                                                               String subLower, String op, String val) {
        Subquery<UUID> sq = query != null ? query.subquery(UUID.class) : null;
        if (sq == null) {
            return cb.isNotNull(root.get(ATTR_ID));
        }
        Root<ScimGroupMembership> mRoot = sq.from(ScimGroupMembership.class);
        sq.select(mRoot.get("memberValue"));
        Predicate base = cb.equal(mRoot.get("group").get(ATTR_ID), root.get(ATTR_ID));
        if ("pr".equals(op) && "display".equals(subLower)) {
            base = cb.and(base, cb.isNotNull(mRoot.get("display")));
        } else if (subLower != null && op != null && !"pr".equals(op)) {
            if ("value".equals(subLower)) {
                try {
                    UUID mid = UUID.fromString(val);
                    Predicate cmp = "ne".equals(op)
                            ? cb.notEqual(mRoot.get("memberValue"), mid)
                            : cb.equal(mRoot.get("memberValue"), mid);
                    base = cb.and(base, cmp);
                } catch (IllegalArgumentException e) {
                    if ("eq".equals(op)) return falsePredicate(cb);
                }
            } else if ("type".equals(subLower)) {
                Predicate cmp = buildComparisonPredicate(cb, mRoot.get("memberType"), op, val, ATTR_USER_TYPE);
                base = cb.and(base, cmp);
            } else if ("display".equals(subLower)) {
                Predicate cmp = buildComparisonPredicate(cb, mRoot.get("display"), op, val, ATTR_DISPLAY_NAME);
                base = cb.and(base, cmp);
            } else if ("$ref".equals(subLower)) {
                String tail = ScimCanonicalizer.extractCanonicalScimResourceTail(val);
                if (tail != null) {
                    int slash = tail.indexOf('/');
                    String expectedType = "Groups".equals(tail.substring(0, slash)) ? "Group" : "User";
                    String idStr = tail.substring(slash + 1);
                    try {
                        UUID mid = UUID.fromString(idStr);
                        Predicate idMatch = cb.equal(mRoot.get("memberValue"), mid);
                        Predicate typeMatch;
                        if ("User".equals(expectedType)) {
                            typeMatch = cb.or(
                                    cb.isNull(mRoot.get("memberType")),
                                    cb.or(
                                            cb.equal(mRoot.get("memberType"), ""),
                                            cb.equal(cb.lower(mRoot.get("memberType")), "user")));
                        } else {
                            typeMatch = cb.and(
                                    cb.isNotNull(mRoot.get("memberType")),
                                    cb.equal(cb.lower(mRoot.get("memberType")), "group"));
                        }
                        Predicate fullMatch = cb.and(idMatch, typeMatch);
                        base = cb.and(base, "ne".equals(op) ? cb.not(fullMatch) : fullMatch);
                    } catch (IllegalArgumentException e) {
                        if ("eq".equals(op)) return falsePredicate(cb);
                    }
                } else if ("eq".equals(op)) {
                    return falsePredicate(cb);
                }
            }
        }
        sq.where(base);
        return cb.exists(sq);
    }

    private static <T> Specification<T> handleJsonCollectionFilter(List<String> tokens, int[] pos, String collectionName, String subAttr, String attrPath) {
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Incomplete filter expression after: " + attrPath);
        }

        final String normalizedSubAttr = resolveJsonFieldKey(collectionName, subAttr);
        if (normalizedSubAttr == null) {
            String opTmp = tokens.get(pos[0]);
            pos[0]++;
            if (!"pr".equalsIgnoreCase(opTmp) && pos[0] < tokens.size()) {
                pos[0]++;
            }
            return (root, query, cb) -> {
                throw new ScimException(400, "invalidFilter", "Unknown sub-attribute '" + subAttr + "' on " + collectionName);
            };
        }

        String operator = tokens.get(pos[0]).toLowerCase(Locale.ROOT);
        pos[0]++;

        if ("pr".equals(operator)) {
            return (root, query, cb) -> {
                String expectedKey = "\"" + normalizedSubAttr + "\"%:%";
                return cb.like(castToString(root.get(getCollectionFieldName(collectionName))), "%" + expectedKey + "%", '\\');
            };
        }

        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Missing value for operator: " + operator);
        }

        String rawValue = tokens.get(pos[0]);
        pos[0]++;
        boolean quoted = rawValue.startsWith("\"") && rawValue.endsWith("\"");
        final String finalValue = unquote(rawValue);

        return (root, query, cb) -> {
            String dbField = getCollectionFieldName(collectionName);
            Expression<String> jsonString = castToString(root.get(dbField));

            String escapedValue = escapeLikeValue(finalValue);

            boolean isBoolean = !quoted && ("true".equalsIgnoreCase(finalValue) || BOOLEAN_FALSE.equalsIgnoreCase(finalValue));
            String jsonAttrPrefix = "\"" + normalizedSubAttr + "\"%:%";
            String jsonSearchFragment;
            if (isBoolean) {
                jsonSearchFragment = jsonAttrPrefix + finalValue.toLowerCase(Locale.ROOT);
            } else {
                jsonSearchFragment = jsonAttrPrefix + "\"" + escapedValue + "\"";
            }

            boolean caseExact = isJsonSubAttributeCaseExact(collectionName, subAttr);
            boolean caseInsensitive = !caseExact;

            return buildJsonOperatorPredicate(cb, jsonString, operator, caseInsensitive, jsonAttrPrefix, jsonSearchFragment, escapedValue);
        };
    }

    private static String resolveJsonFieldKey(String collectionName, String subAttr) {
        String col = collectionName.toLowerCase(Locale.ROOT);
        String sub = subAttr.toLowerCase(Locale.ROOT);
        if ("addresses".equals(col)) {
            return switch (sub) {
                case "formatted" -> "formatted";
                case "streetaddress" -> "streetAddress";
                case "locality" -> "locality";
                case "region" -> "region";
                case "postalcode" -> "postalCode";
                case "country" -> "country";
                case "type" -> "type";
                case "primary" -> "primaryFlag";
                default -> null;
            };
        }
        return switch (sub) {
            case "value" -> "value";
            case "type" -> "type";
            case "display" -> "display";
            case "primary" -> "primaryFlag";
            case "$ref" -> "value";
            default -> null;
        };
    }

    static boolean isJsonSubAttributeCaseExact(String collectionName, String subAttr) {
        String col = collectionName.toLowerCase(Locale.ROOT);
        String sub = subAttr.toLowerCase(Locale.ROOT);
        if ("$ref".equals(sub)) {
            return true;
        }
        if ("value".equals(sub) && ("photos".equals(col) || "x509certificates".equals(col))) {
            return true;
        }
        return false;
    }

    private static Predicate buildJsonOperatorPredicate(CriteriaBuilder cb, Expression<String> jsonString,
                                                            String operator, boolean caseInsensitive,
                                                            String jsonAttrPrefix, String jsonSearchFragment,
                                                            String escapedValue) {
        switch (operator) {
            case "eq":
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + jsonSearchFragment.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like(jsonString, "%" + jsonSearchFragment + "%", '\\');
            case "ne":
                if (caseInsensitive) {
                    return cb.notLike(cb.lower(jsonString), "%" + jsonSearchFragment.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.notLike(jsonString, "%" + jsonSearchFragment + "%", '\\');
            case "co": {
                String coPattern = jsonAttrPrefix + "\"" + "%" + escapedValue + "%";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + coPattern.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like(jsonString, "%" + coPattern + "%", '\\');
            }
            case "sw": {
                String swPattern = jsonAttrPrefix + "\"" + escapedValue + "%";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + swPattern.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like(jsonString, "%" + swPattern + "%", '\\');
            }
            case "ew": {
                String ewPattern = jsonAttrPrefix + "\"" + "%" + escapedValue + "\"";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + ewPattern.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like(jsonString, "%" + ewPattern + "%", '\\');
            }
            default:
                throw new ScimException(400, "invalidFilter", "Operator " + operator + " not supported for JSON collections");
        }
    }

    private static String getCollectionFieldName(String collectionName) {
        if ("phonenumbers".equalsIgnoreCase(collectionName)) {
            return "phoneNumbers";
        }
        if ("x509certificates".equalsIgnoreCase(collectionName)) {
            return "x509Certificates";
        }
        return collectionName.toLowerCase(Locale.ROOT);
    }

    static Instant parseDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e1) {
            try {
                return OffsetDateTime.parse(value).toInstant();
            } catch (DateTimeParseException e2) {
                try {
                    return LocalDateTime.parse(value).toInstant(ZoneOffset.UTC);
                } catch (DateTimeParseException e3) {
                    return null;
                }
            }
        }
    }

    @SuppressWarnings({"unchecked"})
    private static Predicate buildEqNePredicate(CriteriaBuilder cb, Path<?> path, String value,
                                                  boolean caseInsensitive, boolean negate, String attrPath) {
        if (Boolean.class.equals(path.getJavaType()) || boolean.class.equals(path.getJavaType()) || "active".equalsIgnoreCase(attrPath)) {
            if (!"true".equalsIgnoreCase(value) && !BOOLEAN_FALSE.equalsIgnoreCase(value)) {
                throw new ScimException(400, "invalidFilter", "Invalid boolean value for attribute '" + attrPath + "': " + value);
            }
            boolean boolVal = Boolean.parseBoolean(value);
            return negate ? cb.notEqual(path, boolVal) : cb.equal(path, boolVal);
        }
        if (Instant.class.equals(path.getJavaType())) {
            Instant instant = parseDateTime(value);
            if (instant == null) {
                throw new ScimException(400, "invalidFilter", "Invalid dateTime format for attribute '" + attrPath + "': " + value);
            }
            Path<Instant> instantPath = (Path<Instant>) path;
            return negate ? cb.notEqual(instantPath, instant) : cb.equal(instantPath, instant);
        }
        if (UUID.class.equals(path.getJavaType())) {
            UUID uuidVal;
            try {
                uuidVal = UUID.fromString(value);
            } catch (IllegalArgumentException e) {
                throw new ScimException(400, "invalidFilter", "Invalid UUID format for attribute '" + attrPath + "': " + value);
            }
            if (!uuidVal.toString().equalsIgnoreCase(value)) {
                throw new ScimException(400, "invalidFilter", "Invalid UUID format for attribute '" + attrPath + "': " + value);
            }
            Path<UUID> uuidPath = (Path<UUID>) path;
            return negate ? cb.notEqual(uuidPath, uuidVal) : cb.equal(uuidPath, uuidVal);
        }
        if (caseInsensitive) {
            Expression<String> lower = cb.lower((Expression<String>) path);
            return negate ? cb.notEqual(lower, value.toLowerCase(Locale.ROOT)) : cb.equal(lower, value.toLowerCase(Locale.ROOT));
        }
        if (attrPath != null && attrPath.toLowerCase(Locale.ROOT).endsWith("manager.$ref")) {
            String tail = ScimCanonicalizer.extractCanonicalScimResourceTail(value);
            if (tail != null && tail.startsWith("Users/") && path.getParentPath() != null) {
                String mgrIdStr = tail.substring("Users/".length());
                String lowerMgrId = mgrIdStr.toLowerCase(Locale.ROOT);
                String lowerTail = tail.toLowerCase(Locale.ROOT);
                Expression<String> mgrValExpr = path.getParentPath().get("enterpriseManagerValue");
                Expression<String> lowerRefExpr = cb.lower((Expression<String>) path);
                Predicate valMatches = cb.and(
                        cb.isNotNull(mgrValExpr),
                        cb.equal(cb.lower(mgrValExpr), lowerMgrId));
                Predicate refTailMatch = cb.and(
                        cb.isNotNull(path),
                        cb.or(
                                cb.equal(path, value),
                                cb.or(
                                        cb.equal(lowerRefExpr, lowerTail),
                                        cb.like(lowerRefExpr, "%/" + escapeLikeValue(lowerTail), '\\'))));
                Predicate match = cb.or(valMatches, cb.and(cb.isNull(mgrValExpr), refTailMatch));
                return negate ? cb.not(match) : match;
            }
            Predicate exactMatch = cb.and(cb.isNotNull(path), cb.equal(path, value));
            return negate ? cb.not(exactMatch) : exactMatch;
        }
        return negate ? cb.notEqual(path, value) : cb.equal(path, value);
    }

    @SuppressWarnings("unchecked")
    private static Expression<String> castToString(Expression<?> expression) {
        if (expression instanceof JpaExpression<?> jpaExpression) {
            return ((JpaExpression<?>) jpaExpression).cast(String.class);
        }
        return ((Expression<Object>) expression).as(String.class);
    }

    @SuppressWarnings({"unchecked"})
    private static Predicate buildComparisonPredicate(CriteriaBuilder cb, Path<?> path,
                                                       String operator, String value, String attrPath) {
        if (Boolean.class.equals(path.getJavaType()) || boolean.class.equals(path.getJavaType()) || "active".equalsIgnoreCase(attrPath)) {
            if (!"eq".equalsIgnoreCase(operator) && !"ne".equalsIgnoreCase(operator)) {
                throw new ScimException(400, "invalidFilter", "Comparison operator '" + operator + "' is not supported for boolean attribute '" + attrPath + "'");
            }
        }

        if ("co".equalsIgnoreCase(operator) || "sw".equalsIgnoreCase(operator) || "ew".equalsIgnoreCase(operator)) {
            if (Instant.class.equals(path.getJavaType())
                    || Boolean.class.equals(path.getJavaType())
                    || boolean.class.equals(path.getJavaType())
                    || UUID.class.equals(path.getJavaType())) {
                throw new ScimException(400, "invalidFilter", "Operator '" + operator + "' is not supported for attribute: " + attrPath);
            }
        }

        boolean caseInsensitive = isCaseInsensitiveAttribute(attrPath);
        String escaped = escapeLikeValue(value);

        switch (operator) {
            case "eq":
                return buildEqNePredicate(cb, path, value, caseInsensitive, false, attrPath);
            case "ne":
                return buildEqNePredicate(cb, path, value, caseInsensitive, true, attrPath);
            case "co":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), "%" + escaped.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like((Expression<String>) path, "%" + escaped + "%", '\\');
            case "sw":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), escaped.toLowerCase(Locale.ROOT) + "%", '\\');
                }
                return cb.like((Expression<String>) path, escaped + "%", '\\');
            case "ew":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), "%" + escaped.toLowerCase(Locale.ROOT), '\\');
                }
                return cb.like((Expression<String>) path, "%" + escaped, '\\');
            case "gt":
                return buildOrderPredicate(cb, path, value, "gt", attrPath);
            case "ge":
                return buildOrderPredicate(cb, path, value, "ge", attrPath);
            case "lt":
                return buildOrderPredicate(cb, path, value, "lt", attrPath);
            case "le":
                return buildOrderPredicate(cb, path, value, "le", attrPath);
            default:
                throw new ScimException(400, "invalidFilter", "Unknown filter operator: " + operator);
        }
    }

    @SuppressWarnings({"unchecked"})
    private static Predicate buildOrderPredicate(CriteriaBuilder cb, Path<?> path, String value, String op, String attrPath) {
        if (Instant.class.equals(path.getJavaType())) {
            Instant instant = parseDateTime(value);
            if (instant == null) {
                throw new ScimException(400, "invalidFilter", "Invalid dateTime format for attribute '" + attrPath + "': " + value);
            }
            Path<Instant> instantPath = (Path<Instant>) path;
            return switch (op) {
                case "gt" -> cb.greaterThan(instantPath, instant);
                case "ge" -> cb.greaterThanOrEqualTo(instantPath, instant);
                case "lt" -> cb.lessThan(instantPath, instant);
                case "le" -> cb.lessThanOrEqualTo(instantPath, instant);
                default -> throw new ScimException(400, "invalidFilter", "Unknown operator: " + op);
            };
        }

        if (UUID.class.equals(path.getJavaType())) {
            throw new ScimException(400, "invalidFilter", "Comparison operator '" + op + "' is not supported for attribute: " + attrPath);
        }

        Path<String> stringPath = (Path<String>) path;
        if (isCaseInsensitiveAttribute(attrPath)) {
            Expression<String> lowerExpr = cb.lower(stringPath);
            String lowerVal = value.toLowerCase(Locale.ROOT);
            return switch (op) {
                case "gt" -> cb.greaterThan(lowerExpr, lowerVal);
                case "ge" -> cb.greaterThanOrEqualTo(lowerExpr, lowerVal);
                case "lt" -> cb.lessThan(lowerExpr, lowerVal);
                case "le" -> cb.lessThanOrEqualTo(lowerExpr, lowerVal);
                default -> throw new ScimException(400, "invalidFilter", "Unknown operator: " + op);
            };
        }
        return switch (op) {
            case "gt" -> cb.greaterThan(stringPath, value);
            case "ge" -> cb.greaterThanOrEqualTo(stringPath, value);
            case "lt" -> cb.lessThan(stringPath, value);
            case "le" -> cb.lessThanOrEqualTo(stringPath, value);
            default -> throw new ScimException(400, "invalidFilter", "Unknown operator: " + op);
        };
    }

    // ── ATTRIBUTE PATH RESOLUTION ─────────────────────────

    private static Path<?> resolveAttributePath(Root<?> root, String attrPath, boolean isUser) {
        return isUser ? resolveUserAttributePath(root, attrPath) : resolveGroupAttributePath(root, attrPath);
    }

    private static Path<?> resolveUserAttributePath(Root<?> root, String attrPath) {
        String lowerPath = attrPath.toLowerCase(Locale.ROOT);

        if (lowerPath.startsWith("meta.")) {
            String sub = lowerPath.substring(5);
            return switch (sub) {
                case META_ATTR_CREATED -> root.get(ATTR_CREATED_AT);
                case "lastmodified" -> root.get(ATTR_LAST_MODIFIED);
                case "version" -> root.get("version");
                default -> throw new ScimException(400, "invalidFilter", "Unknown meta attribute: " + attrPath.substring(5));
            };
        }

        if (lowerPath.startsWith("name.")) {
            String sub = lowerPath.substring(5);
            return switch (sub) {
                case "familyname" -> root.get("nameFamilyName");
                case "givenname" -> root.get("nameGivenName");
                case "formatted" -> root.get("nameFormatted");
                case "middlename" -> root.get("nameMiddleName");
                case "honorificprefix" -> root.get("nameHonorificPrefix");
                case "honorificsuffix" -> root.get("nameHonorificSuffix");
                default -> throw new ScimException(400, "invalidFilter", "Unknown name sub-attribute: " + attrPath.substring(5));
            };
        }

        if (lowerPath.startsWith(ENTERPRISE_URN_PREFIX)) {
            String sub = lowerPath.substring(ENTERPRISE_URN_PREFIX.length());
            return switch (sub) {
                case "employeenumber" -> root.get("enterpriseEmployeeNumber");
                case "costcenter" -> root.get("enterpriseCostCenter");
                case "organization" -> root.get("enterpriseOrganization");
                case "division" -> root.get("enterpriseDivision");
                case "department" -> root.get("enterpriseDepartment");
                case "manager", "manager.value" -> root.get("enterpriseManagerValue");
                case "manager.$ref" -> root.get("enterpriseManagerRef");
                case "manager.displayname" -> root.get("enterpriseManagerDisplay");
                default -> throw new ScimException(400, "invalidFilter", "Unknown enterprise attribute: " + attrPath.substring(ENTERPRISE_URN_PREFIX.length()));
            };
        }

        return switch (lowerPath) {
            case "id" -> root.get(ATTR_ID);
            case "username" -> root.get(ATTR_USER_NAME);
            case "externalid" -> root.get(ATTR_EXTERNAL_ID);
            case ATTR_DISPLAY_NAME_LOWER -> root.get(ATTR_DISPLAY_NAME);
            case "nickname" -> root.get(ATTR_NICK_NAME);
            case ATTR_TITLE -> root.get(ATTR_TITLE);
            case "usertype" -> root.get(ATTR_USER_TYPE);
            case "profileurl" -> root.get("profileUrl");
            case "preferredlanguage" -> root.get(ATTR_PREFERRED_LANGUAGE);
            case ATTR_LOCALE -> root.get(ATTR_LOCALE);
            case ATTR_TIMEZONE -> root.get(ATTR_TIMEZONE);
            case "active" -> root.get("active");
            default -> throw new ScimException(400, "invalidFilter", "Unknown attribute: " + attrPath);
        };
    }

    private static Path<?> resolveGroupAttributePath(Root<?> root, String attrPath) {
        String lowerPath = attrPath.toLowerCase(Locale.ROOT);

        if (lowerPath.startsWith("meta.")) {
            String sub = lowerPath.substring(5);
            return switch (sub) {
                case META_ATTR_CREATED -> root.get(ATTR_CREATED_AT);
                case "lastmodified" -> root.get(ATTR_LAST_MODIFIED);
                case "version" -> root.get("version");
                default -> throw new ScimException(400, "invalidFilter", "Unknown meta attribute: " + attrPath.substring(5));
            };
        }

        return switch (lowerPath) {
            case "id" -> root.get(ATTR_ID);
            case ATTR_DISPLAY_NAME_LOWER -> root.get(ATTR_DISPLAY_NAME);
            case "externalid" -> root.get(ATTR_EXTERNAL_ID);
            default -> throw new ScimException(400, "invalidFilter", "Unknown attribute: " + attrPath);
        };
    }

    private static Predicate falsePredicate(CriteriaBuilder cb) {
        Predicate p = cb.disjunction();
        if (p != null) {
            return p;
        }
        return cb.equal(cb.literal(1), 0);
    }

    private static Predicate truePredicate(CriteriaBuilder cb) {
        Predicate p = cb.conjunction();
        if (p != null) {
            return p;
        }
        return cb.equal(cb.literal(1), 1);
    }

    private static Predicate orAll(CriteriaBuilder cb, Predicate first, Predicate... rest) {
        Predicate acc = first;
        for (Predicate p : rest) {
            acc = cb.or(acc, p);
        }
        return acc;
    }

    // ── TOKENIZER ─────────────────────────────────────────

    private static List<String> tokenize(String filter) {
        List<String> tokens = new ArrayList<>(filter.length() / 4 + 4);
        Matcher matcher = TOKEN_PATTERN.matcher(filter);
        int lastEnd = 0;
        while (matcher.find()) {
            for (int i = lastEnd; i < matcher.start(); i++) {
                if (!Character.isWhitespace(filter.charAt(i))) {
                    throw new ScimException(400, "invalidFilter",
                            "Unexpected character in filter at position " + i + ": " + filter.charAt(i));
                }
            }
            String token = matcher.group();
            if (lastEnd == matcher.start() && !tokens.isEmpty()) {
                String prev = tokens.get(tokens.size() - 1);
                if (token.startsWith("\"") && !"(".equals(prev) && !"[".equals(prev)) {
                    throw new ScimException(400, "invalidFilter",
                            "Missing whitespace before quoted value at position " + matcher.start());
                }
                if (prev.endsWith("\"") && !")".equals(token) && !"]".equals(token)) {
                    throw new ScimException(400, "invalidFilter",
                            "Missing whitespace after quoted value at position " + matcher.start());
                }
            }
            tokens.add(token);
            lastEnd = matcher.end();
        }
        for (int i = lastEnd; i < filter.length(); i++) {
            if (!Character.isWhitespace(filter.charAt(i))) {
                throw new ScimException(400, "invalidFilter",
                        "Unexpected character in filter at position " + i + ": " + filter.charAt(i));
            }
        }
        if (tokens.isEmpty()) {
            throw new ScimException(400, "invalidFilter", "Empty filter expression");
        }
        return tokens;
    }

    // ── CASE SENSITIVITY ──────────────────────────────────

    // RFC 7643 §2.2 & schema definitions: id, externalId, profileUrl, manager.value, manager.$ref are caseExact=true
    private static final Set<String> CASE_INSENSITIVE_ATTRS = Set.of(
            "username", ATTR_DISPLAY_NAME_LOWER, "nickname", ATTR_TITLE, "usertype",
            "preferredlanguage", ATTR_LOCALE, ATTR_TIMEZONE,
            "name.familyname", "name.givenname", "name.formatted", "name.middlename",
            "name.honorificprefix", "name.honorificsuffix",
            "employeenumber", "costcenter", "organization", "division", "department", "manager.displayname");

    static boolean isCaseInsensitiveAttribute(String attrPath) {
        String stripped = attrPath;
        String lower = attrPath.toLowerCase(Locale.ROOT);
        if (lower.startsWith(CORE_USER_URN_PREFIX)) {
            stripped = attrPath.substring(CORE_USER_URN_PREFIX.length());
        } else if (lower.startsWith(CORE_GROUP_URN_PREFIX)) {
            stripped = attrPath.substring(CORE_GROUP_URN_PREFIX.length());
        } else if (lower.startsWith(ENTERPRISE_URN_PREFIX)) {
            stripped = attrPath.substring(ENTERPRISE_URN_PREFIX.length());
        }
        return CASE_INSENSITIVE_ATTRS.contains(stripped.toLowerCase(Locale.ROOT));
    }

    public static boolean isSortByCaseExact(String rawSortBy) {
        if (rawSortBy == null || rawSortBy.isBlank()) {
            return false;
        }
        String stripped = rawSortBy.trim();
        String lower = stripped.toLowerCase(Locale.ROOT);
        if (lower.startsWith(CORE_USER_URN_PREFIX)) {
            stripped = stripped.substring(CORE_USER_URN_PREFIX.length());
        } else if (lower.startsWith(CORE_GROUP_URN_PREFIX)) {
            stripped = stripped.substring(CORE_GROUP_URN_PREFIX.length());
        } else if (lower.startsWith(ENTERPRISE_URN_PREFIX)) {
            stripped = stripped.substring(ENTERPRISE_URN_PREFIX.length());
        }
        String sLower = stripped.toLowerCase(Locale.ROOT);
        return switch (sLower) {
            case "id", "externalid", "profileurl", "meta.created", "meta.lastmodified", "meta.location", "meta.version",
                 "manager.value", "manager.$ref", "photos.value", "x509certificates.value", "active" -> true;
            default -> false;
        };
    }

    // ── SORTING ───────────────────────────────────────────

    public static String resolveUserSortAttribute(String sortBy) {
        if (sortBy == null) return ATTR_USER_NAME;

        String stripped = stripCoreUrnPrefix(sortBy, true);
        String lowerSortBy = stripped.toLowerCase(Locale.ROOT);
        if (lowerSortBy.equals("emails") || lowerSortBy.equals("emails.value")) {
            return "emails";
        }
        if (JSON_COLLECTIONS.stream().anyMatch(lowerSortBy::startsWith) || lowerSortBy.startsWith("groups")) {
            throw new ScimException(400, "invalidValue", "Sorting on multi-valued complex attributes is not supported.");
        }
        if (lowerSortBy.startsWith(ENTERPRISE_URN_PREFIX)) {
            String sub = lowerSortBy.substring(ENTERPRISE_URN_PREFIX.length());
            return switch (sub) {
                case "employeenumber" -> "enterpriseEmployeeNumber";
                case "costcenter" -> "enterpriseCostCenter";
                case "organization" -> "enterpriseOrganization";
                case "division" -> "enterpriseDivision";
                case "department" -> "enterpriseDepartment";
                default -> ATTR_USER_NAME;
            };
        }

        return switch (lowerSortBy) {
            case "username" -> ATTR_USER_NAME;
            case "name.familyname" -> "nameFamilyName";
            case "name.givenname" -> "nameGivenName";
            case "name.formatted" -> "nameFormatted";
            case "name.middlename" -> "nameMiddleName";
            case "name.honorificprefix" -> "nameHonorificPrefix";
            case "name.honorificsuffix" -> "nameHonorificSuffix";
            case ATTR_DISPLAY_NAME_LOWER -> ATTR_DISPLAY_NAME;
            case "nickname" -> ATTR_NICK_NAME;
            case "profileurl" -> "profileUrl";
            case ATTR_TITLE -> ATTR_TITLE;
            case "usertype" -> ATTR_USER_TYPE;
            case "preferredlanguage" -> ATTR_PREFERRED_LANGUAGE;
            case ATTR_LOCALE -> ATTR_LOCALE;
            case ATTR_TIMEZONE -> ATTR_TIMEZONE;
            case "active" -> "active";
            case "externalid" -> ATTR_EXTERNAL_ID;
            case "meta.created" -> ATTR_CREATED_AT;
            case "meta.lastmodified" -> ATTR_LAST_MODIFIED;
            case ATTR_ID -> ATTR_ID;
            default -> ATTR_USER_NAME;
        };
    }

    public static String resolveGroupSortAttribute(String sortBy) {
        if (sortBy == null) return ATTR_DISPLAY_NAME;
        String stripped = stripCoreUrnPrefix(sortBy, false);
        String lower = stripped.toLowerCase(Locale.ROOT);
        if (lower.startsWith("members")) {
            throw new ScimException(400, "invalidValue", "Sorting on multi-valued complex attributes is not supported.");
        }
        return switch (lower) {
            case ATTR_DISPLAY_NAME_LOWER -> ATTR_DISPLAY_NAME;
            case "externalid" -> ATTR_EXTERNAL_ID;
            case "meta.created" -> ATTR_CREATED_AT;
            case "meta.lastmodified" -> ATTR_LAST_MODIFIED;
            case ATTR_ID -> ATTR_ID;
            default -> ATTR_DISPLAY_NAME;
        };
    }
}
