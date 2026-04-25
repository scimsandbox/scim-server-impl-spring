package de.palsoftware.scim.server.impl.scim.filter;

import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import jakarta.persistence.criteria.*;
import org.hibernate.query.criteria.JpaExpression;

import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses SCIM filter expressions (RFC 7644 §3.4.2.2) into JPA Specifications.
 * Supports: eq, ne, co, sw, ew, pr, gt, ge, lt, le, and, or, not, grouping ().
 */
public class ScimFilterParser {

    private ScimFilterParser() {
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
    // Common attribute name constants
    private static final String ATTR_USER_NAME = "userName";
    private static final String ATTR_DISPLAY_NAME = "displayName";
    private static final String ATTR_EXTERNAL_ID = "externalId";
    private static final String ATTR_ID = "id";
    private static final String ATTR_TITLE = "title";

    // Lowercase constants used as switch case labels (attribute matching is case-insensitive)
    private static final String ATTR_DISPLAY_NAME_LOWER = "displayname";
    private static final String BOOLEAN_FALSE = "false";

    // URN prefix constants (lowercase for case-insensitive matching)
    private static final String CORE_USER_URN_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:user:";
    private static final String CORE_GROUP_URN_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:group:";
    private static final String ENTERPRISE_URN_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:";

    // Token patterns
    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            "\\(|\\)|\\[|\\]|" +                           // Grouping
            "\"(?:[^\"\\\\]|\\\\.)*+\"|" +           // Quoted string (possessive quantifier)
            "\\b(?:true|false)\\b|" +               // Boolean
            "\\b(?:and|or|not)\\b|" +               // Logical operators
            "\\b(?:eq|ne|co|sw|ew|pr|gt|ge|lt|le)\\b|" + // Comparison operators
            "[\\w.:]+",                              // Attribute paths (including URN prefixes)
            Pattern.CASE_INSENSITIVE
    );

    // ── USER FILTER ─────────────────────────────────────

    public static Specification<ScimUser> parseUserFilter(String filter, UUID workspaceId) {
        if (filter == null || filter.isBlank()) {
            return (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
        }
        try {
            List<String> tokens = tokenize(filter);
            int[] pos = {0};
            Specification<ScimUser> spec = parseOrExpression(tokens, pos, true);
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

    // ── GROUP FILTER ─────────────────────────────────────

    public static Specification<ScimGroup> parseGroupFilter(String filter, UUID workspaceId) {
        if (filter == null || filter.isBlank()) {
            return (root, query, cb) -> cb.equal(root.get(ATTR_WORKSPACE).get(ATTR_ID), workspaceId);
        }
        try {
            List<String> tokens = tokenize(filter);
            int[] pos = {0};
            Specification<ScimGroup> spec = parseOrExpression(tokens, pos, false);
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

    // ── RECURSIVE DESCENT PARSER ─────────────────────────

    private static <T> Specification<T> parseOrExpression(List<String> tokens, int[] pos, boolean isUser) {
        return parseOrExpression(tokens, pos, isUser, null);
    }

    private static <T> Specification<T> parseOrExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath) {
        Specification<T> left = parseAndExpression(tokens, pos, isUser, parentPath);
        while (pos[0] < tokens.size() && "or".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> right = parseAndExpression(tokens, pos, isUser, parentPath);
            left = left.or(right);
        }
        return left;
    }

    private static <T> Specification<T> parseAndExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath) {
        Specification<T> left = parseNotExpression(tokens, pos, isUser, parentPath);
        while (pos[0] < tokens.size() && "and".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> right = parseNotExpression(tokens, pos, isUser, parentPath);
            left = left.and(right);
        }
        return left;
    }

    private static <T> Specification<T> parseNotExpression(List<String> tokens, int[] pos, boolean isUser, String parentPath) {
        if (pos[0] < tokens.size() && "not".equalsIgnoreCase(tokens.get(pos[0]))) {
            pos[0]++;
            Specification<T> inner = parseAtom(tokens, pos, isUser, parentPath);
            return Specification.not(inner);
        }
        return parseAtom(tokens, pos, isUser, parentPath);
    }

    private static final Set<String> JSON_COLLECTIONS = Set.of(
            "emails", "phonenumbers", "addresses", "entitlements", "roles", "ims", "photos", "x509certificates", "groups"
    );

    // RFC 7644 §3.4.2.2: Strip core schema URN prefix for attribute resolution
    private static String stripCoreUrnPrefix(String attrPath, boolean isUser) {
        String lower = attrPath.toLowerCase();
        if (isUser && lower.startsWith(CORE_USER_URN_PREFIX)) {
            return attrPath.substring(CORE_USER_URN_PREFIX.length());
        }
        if (!isUser && lower.startsWith(CORE_GROUP_URN_PREFIX)) {
            return attrPath.substring(CORE_GROUP_URN_PREFIX.length());
        }
        return attrPath;
    }

    // Escape LIKE wildcard characters in filter values to prevent injection
    private static String escapeLikeValue(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static <T> Specification<T> parseAtom(List<String> tokens, int[] pos, boolean isUser, String parentPath) {
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Unexpected end of filter expression");
        }

        String token = tokens.get(pos[0]);

        // Grouping
        if ("(".equals(token)) {
            pos[0]++;
            Specification<T> inner = parseOrExpression(tokens, pos, isUser, parentPath);
            if (pos[0] >= tokens.size() || !")".equals(tokens.get(pos[0]))) {
                throw new ScimException(400, "invalidFilter", "Missing closing parenthesis");
            }
            pos[0]++;
            return inner;
        }

        // Attribute comparison or presence
        String attrPath = token;
        pos[0]++;

        // Check for value path filter (e.g. emails[type eq "work"])
        if (pos[0] < tokens.size() && "[".equals(tokens.get(pos[0]))) {
            return parseValuePathBranch(tokens, pos, attrPath, isUser);
        }

        if (parentPath != null) {
            attrPath = parentPath + "." + attrPath;
        }

        // RFC 7644 §3.4.2.2: Strip core schema URN prefix for attribute resolution
        attrPath = stripCoreUrnPrefix(attrPath, isUser);

        final String finalAttrPath = attrPath;

        // Handle JSON collections (e.g. emails.value eq "test")
        if (isUser && finalAttrPath.contains(".")) {
            String[] parts = finalAttrPath.split("\\.", 2);
            if (JSON_COLLECTIONS.contains(parts[0].toLowerCase())) {
                return handleJsonCollectionFilter(tokens, pos, parts[0], parts[1], finalAttrPath);
            }
        }

        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Incomplete filter expression after: " + finalAttrPath);
        }

        return parseOperatorAndValue(tokens, pos, finalAttrPath, isUser);
    }

    private static <T> Specification<T> parseOperatorAndValue(List<String> tokens, int[] pos, String attrPath, boolean isUser) {
        String operator = tokens.get(pos[0]).toLowerCase();
        pos[0]++;

        // Presence operator (no value)
        if ("pr".equals(operator)) {
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

        // Remove quotes from string values
        String value = rawValue;
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }

        final String finalValue = value;

        return (root, query, cb) -> {
            Path<?> path = resolveAttributePath(root, attrPath, isUser);
            return buildComparisonPredicate(cb, path, operator, finalValue, attrPath);
        };
    }

    private static <T> Specification<T> parseValuePathBranch(List<String> tokens, int[] pos, String attrPath, boolean isUser) {
        pos[0]++; // consume [
        // Strip core URN prefix from the parent path before passing to inner filter
        String normalizedParent = stripCoreUrnPrefix(attrPath, isUser);
        Specification<T> inner = parseOrExpression(tokens, pos, isUser, normalizedParent);
        if (pos[0] >= tokens.size() || !"]".equals(tokens.get(pos[0]))) {
            throw new ScimException(400, "invalidFilter", "Missing closing bracket for value path filter");
        }
        pos[0]++; // consume ]
        return inner;
    }

    private static <T> Specification<T> handleJsonCollectionFilter(List<String> tokens, int[] pos, String collectionName, String subAttr, String attrPath) {
        if (pos[0] >= tokens.size()) {
            throw new ScimException(400, "invalidFilter", "Incomplete filter expression after: " + attrPath);
        }

        // RFC 7644 §3.4.2.2: Attribute names are case-insensitive; normalize sub-attribute
        final String normalizedSubAttr = subAttr.toLowerCase();

        String operator = tokens.get(pos[0]).toLowerCase();
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

        String value = rawValue;
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }

        final String finalValue = value;

        return (root, query, cb) -> {
            String dbField = getCollectionFieldName(collectionName);
            Expression<String> jsonString = castToString(root.get(dbField));

            // Escape LIKE wildcards in the filter value
            String escapedValue = escapeLikeValue(finalValue);

            // For boolean values vs string values in JSON
            boolean isBoolean = "true".equalsIgnoreCase(finalValue) || BOOLEAN_FALSE.equalsIgnoreCase(finalValue);
            String jsonAttrPrefix = "\"" + normalizedSubAttr + "\"%:%";
            String jsonSearchFragment;
            if (isBoolean) {
                jsonSearchFragment = jsonAttrPrefix + finalValue.toLowerCase();
            } else {
                jsonSearchFragment = jsonAttrPrefix + "\"" + escapedValue + "\"";
            }

            boolean caseInsensitive = isCaseInsensitiveAttribute(attrPath) || "value".equals(normalizedSubAttr) || "type".equals(normalizedSubAttr) || "display".equals(normalizedSubAttr);

            return buildJsonOperatorPredicate(cb, jsonString, operator, caseInsensitive, jsonAttrPrefix, jsonSearchFragment, escapedValue);
        };
    }

    private static Predicate buildJsonOperatorPredicate(CriteriaBuilder cb, Expression<String> jsonString,
                                                            String operator, boolean caseInsensitive,
                                                            String jsonAttrPrefix, String jsonSearchFragment,
                                                            String escapedValue) {
        switch (operator) {
            case "eq":
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + jsonSearchFragment.toLowerCase() + "%", '\\');
                }
                return cb.like(jsonString, "%" + jsonSearchFragment + "%", '\\');
            case "ne":
                if (caseInsensitive) {
                    return cb.notLike(cb.lower(jsonString), "%" + jsonSearchFragment.toLowerCase() + "%", '\\');
                }
                return cb.notLike(jsonString, "%" + jsonSearchFragment + "%", '\\');
            case "co": {
                // Contains: match sub-attribute key followed by any value containing the search term
                String coPattern = jsonAttrPrefix + "\"" + "%" + escapedValue + "%";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + coPattern.toLowerCase() + "%", '\\');
                }
                return cb.like(jsonString, "%" + coPattern + "%", '\\');
            }
            case "sw": {
                // Starts with: match sub-attribute key followed by value starting with the search term
                String swPattern = jsonAttrPrefix + "\"" + escapedValue + "%";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + swPattern.toLowerCase() + "%", '\\');
                }
                return cb.like(jsonString, "%" + swPattern + "%", '\\');
            }
            case "ew": {
                // Ends with: match sub-attribute key followed by value ending with the search term
                String ewPattern = jsonAttrPrefix + "\"" + "%" + escapedValue + "\"";
                if (caseInsensitive) {
                    return cb.like(cb.lower(jsonString), "%" + ewPattern.toLowerCase() + "%", '\\');
                }
                return cb.like(jsonString, "%" + ewPattern + "%", '\\');
            }
            default:
                // gt, ge, lt, le are not reliably supported via LIKE matching on JSON columns.
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
        return collectionName.toLowerCase();
    }

    @SuppressWarnings({"unchecked"})
    private static Predicate buildEqNePredicate(CriteriaBuilder cb, Path<?> path, String value,
                                                  boolean caseInsensitive, boolean negate) {
        if ("true".equalsIgnoreCase(value) || BOOLEAN_FALSE.equalsIgnoreCase(value)) {
            boolean boolVal = Boolean.parseBoolean(value);
            return negate ? cb.notEqual(path, boolVal) : cb.equal(path, boolVal);
        }
        if (caseInsensitive) {
            Expression<String> lower = cb.lower((Expression<String>) path);
            return negate ? cb.notEqual(lower, value.toLowerCase()) : cb.equal(lower, value.toLowerCase());
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
        // RFC 7644 §3.4.2.2 + RFC 7643 §2.2: case sensitivity determined by caseExact attribute
        boolean caseInsensitive = isCaseInsensitiveAttribute(attrPath);

        // Escape LIKE wildcards in filter values to prevent injection
        String escaped = escapeLikeValue(value);

        switch (operator) {
            case "eq":
                return buildEqNePredicate(cb, path, value, caseInsensitive, false);

            case "ne":
                return buildEqNePredicate(cb, path, value, caseInsensitive, true);

            case "co":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), "%" + escaped.toLowerCase() + "%", '\\');
                }
                return cb.like((Expression<String>) path, "%" + escaped + "%", '\\');

            case "sw":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), escaped.toLowerCase() + "%", '\\');
                }
                return cb.like((Expression<String>) path, escaped + "%", '\\');

            case "ew":
                if (caseInsensitive) {
                    return cb.like(cb.lower((Expression<String>) path), "%" + escaped.toLowerCase(), '\\');
                }
                return cb.like((Expression<String>) path, "%" + escaped, '\\');

            case "gt":
                return buildOrderPredicate(cb, path, value, "gt");
            case "ge":
                return buildOrderPredicate(cb, path, value, "ge");
            case "lt":
                return buildOrderPredicate(cb, path, value, "lt");
            case "le":
                return buildOrderPredicate(cb, path, value, "le");

            default:
                throw new ScimException(400, "invalidFilter", "Unknown filter operator: " + operator);
        }
    }

    @SuppressWarnings({"unchecked"})
    private static Predicate buildOrderPredicate(CriteriaBuilder cb, Path<?> path, String value, String op) {
        // Try as datetime
        try {
            Instant instant = Instant.parse(value);
            Path<Instant> instantPath = (Path<Instant>) path;
            return switch (op) {
                case "gt" -> cb.greaterThan(instantPath, instant);
                case "ge" -> cb.greaterThanOrEqualTo(instantPath, instant);
                case "lt" -> cb.lessThan(instantPath, instant);
                case "le" -> cb.lessThanOrEqualTo(instantPath, instant);
                default -> throw new ScimException(400, "invalidFilter", "Unknown operator: " + op);
            };
        } catch (Exception e) {
            // Fall through to string comparison
        }

        Path<String> stringPath = (Path<String>) path;
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
        if (isUser) {
            return resolveUserAttributePath(root, attrPath);
        } else {
            return resolveGroupAttributePath(root, attrPath);
        }
    }

    private static Path<?> resolveUserAttributePath(Root<?> root, String attrPath) {
        // RFC 7644 §3.4.2.2: Attribute names used in filters are case insensitive
        String lowerPath = attrPath.toLowerCase();

        // Handle meta sub-attributes
        if (lowerPath.startsWith("meta.")) {
            String sub = lowerPath.substring(5);
            return switch (sub) {
                case META_ATTR_CREATED -> root.get(ATTR_CREATED_AT);
                case "lastmodified" -> root.get(ATTR_LAST_MODIFIED);
                default -> throw new ScimException(400, "invalidFilter", "Unknown meta attribute: " + attrPath.substring(5));
            };
        }

        // Handle name sub-attributes
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

        // Handle enterprise extension attributes (case-insensitive URN prefix)
        if (lowerPath.startsWith(ENTERPRISE_URN_PREFIX)) {
            String sub = lowerPath.substring(ENTERPRISE_URN_PREFIX.length());
            return switch (sub) {
                case "employeenumber" -> root.get("enterpriseEmployeeNumber");
                case "costcenter" -> root.get("enterpriseCostCenter");
                case "organization" -> root.get("enterpriseOrganization");
                case "division" -> root.get("enterpriseDivision");
                case "department" -> root.get("enterpriseDepartment");
                default -> throw new ScimException(400, "invalidFilter", "Unknown enterprise attribute: " + attrPath.substring(ENTERPRISE_URN_PREFIX.length()));
            };
        }

        // Direct attributes (case-insensitive matching)
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
        // RFC 7644 §3.4.2.2: Attribute names used in filters are case insensitive
        String lowerPath = attrPath.toLowerCase();

        if (lowerPath.startsWith("meta.")) {
            String sub = lowerPath.substring(5);
            return switch (sub) {
                case META_ATTR_CREATED -> root.get(ATTR_CREATED_AT);
                case "lastmodified" -> root.get(ATTR_LAST_MODIFIED);
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

    // ── TOKENIZER ─────────────────────────────────────────

    private static List<String> tokenize(String filter) {
        List<String> tokens = new ArrayList<>(filter.length() / 4 + 4);
        Matcher matcher = TOKEN_PATTERN.matcher(filter);
        while (matcher.find()) {
            tokens.add(matcher.group());
        }
        if (tokens.isEmpty()) {
            throw new ScimException(400, "invalidFilter", "Empty filter expression");
        }
        return tokens;
    }

    // ── CASE SENSITIVITY ──────────────────────────────────

    // RFC 7643 §2.2: case sensitivity determined by caseExact attribute characteristic
    // All entries normalized to lowercase for case-insensitive lookup
    // Note: externalId has caseExact=true per RFC 7643 §3.1, so it is NOT included
    private static final Set<String> CASE_INSENSITIVE_ATTRS = Set.of(
            "username", ATTR_DISPLAY_NAME_LOWER, "nickname", ATTR_TITLE, "usertype",
            "preferredlanguage", ATTR_LOCALE, ATTR_TIMEZONE, "profileurl",
            "name.familyname", "name.givenname", "name.formatted", "name.middlename",
            "name.honorificprefix", "name.honorificsuffix");

    private static boolean isCaseInsensitiveAttribute(String attrPath) {
        // Strip any known URN prefix before checking
        String stripped = attrPath;
        String lower = attrPath.toLowerCase();
        if (lower.startsWith(CORE_USER_URN_PREFIX)) {
            stripped = attrPath.substring(CORE_USER_URN_PREFIX.length());
        } else if (lower.startsWith(CORE_GROUP_URN_PREFIX)) {
            stripped = attrPath.substring(CORE_GROUP_URN_PREFIX.length());
        }
        return CASE_INSENSITIVE_ATTRS.contains(stripped.toLowerCase());
    }

    // ── SORTING ───────────────────────────────────────────

    public static String resolveUserSortAttribute(String sortBy) {
        if (sortBy == null) return ATTR_USER_NAME;
        
        String lowerSortBy = sortBy.toLowerCase();
        if (JSON_COLLECTIONS.stream().anyMatch(lowerSortBy::startsWith)) {
            throw new ScimException(400, "invalidValue", "Sorting on multi-valued complex attributes is not supported.");
        }

        return switch (sortBy) {
            case ATTR_USER_NAME -> ATTR_USER_NAME;
            case "name.familyName" -> "nameFamilyName";
            case "name.givenName" -> "nameGivenName";
            case ATTR_DISPLAY_NAME -> ATTR_DISPLAY_NAME;
            case ATTR_TITLE -> ATTR_TITLE;
            case ATTR_EXTERNAL_ID -> ATTR_EXTERNAL_ID;
            case "meta.created" -> ATTR_CREATED_AT;
            case "meta.lastModified" -> ATTR_LAST_MODIFIED;
            case ATTR_ID -> ATTR_ID;
            default -> ATTR_USER_NAME;
        };
    }

    public static String resolveGroupSortAttribute(String sortBy) {
        if (sortBy == null) return ATTR_DISPLAY_NAME;
        return switch (sortBy) {
            case ATTR_DISPLAY_NAME -> ATTR_DISPLAY_NAME;
            case ATTR_EXTERNAL_ID -> ATTR_EXTERNAL_ID;
            case "meta.created" -> ATTR_CREATED_AT;
            case "meta.lastModified" -> ATTR_LAST_MODIFIED;
            case ATTR_ID -> ATTR_ID;
            default -> ATTR_DISPLAY_NAME;
        };
    }
}
