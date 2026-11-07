package de.palsoftware.scim.server.impl.scim.patch;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterEvaluator;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser.FilterNode;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
import de.palsoftware.scim.server.impl.scim.validation.ScimCanonicalizer;
import de.palsoftware.scim.server.impl.scim.validation.ScimCertificateValidator;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimUserAddress;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
import de.palsoftware.scim.server.impl.model.ScimUserEntitlement;
import de.palsoftware.scim.server.impl.model.ScimUserIm;
import de.palsoftware.scim.server.impl.model.ScimUserPhoneNumber;
import de.palsoftware.scim.server.impl.model.ScimUserPhoto;
import de.palsoftware.scim.server.impl.model.ScimUserRole;
import de.palsoftware.scim.server.impl.model.ScimUserX509Certificate;

import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SCIM PATCH operation engine per RFC 7644 §3.5.2.
 * Supports add, replace, remove operations with path filters.
 */
public class ScimPatchEngine {

    private ScimPatchEngine() {
        /* Utility class */
    }

    private static final String ENTERPRISE_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String CORE_USER_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:User:";

    private static String stripPathPrefix(String path) {
        if (path == null) {
            return null;
        }
        String trimmed = path.trim();
        if (trimmed.regionMatches(true, 0, CORE_USER_PREFIX, 0, CORE_USER_PREFIX.length())) {
            return trimmed.substring(CORE_USER_PREFIX.length());
        }
        return trimmed;
    }

    // Pattern: attrName[filterExpr].subAttr
    private static final Pattern FILTERED_PATH = Pattern.compile("^(\\w+)\\[(.+)](?:\\.([\\w$]+))?$");

    // Multi-valued attribute keys
    private static final String KEY_VALUE = "value";
    private static final String KEY_DISPLAY = "display";
    private static final String KEY_PRIMARY = "primary";
    private static final String KEY_TYPE = "type";
    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_FORMATTED = "formatted";
    private static final String VALUE_OTHER = "other";

    // Multi-valued collection names
    private static final String ATTR_EMAILS = "emails";
    private static final String ATTR_PHONE_NUMBERS = "phoneNumbers";
    private static final String ATTR_ADDRESSES = "addresses";
    private static final String ATTR_ENTITLEMENTS = "entitlements";
    private static final String ATTR_ROLES = "roles";
    private static final String ATTR_IMS = "ims";
    private static final String ATTR_PHOTOS = "photos";
    private static final String ATTR_X509 = "x509Certificates";

    private static final Set<String> EMAIL_TYPES = Set.of("work", "home", VALUE_OTHER);
    private static final Set<String> PHONE_TYPES = Set.of("work", "home", "mobile", "fax", "pager", VALUE_OTHER);
    private static final Set<String> IM_TYPES = Set.of("aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo", VALUE_OTHER);
    private static final Set<String> PHOTO_TYPES = Set.of("photo", "thumbnail");
    private static final Set<String> ADDRESS_TYPES = Set.of("work", "home", VALUE_OTHER);

    private static boolean isReadOnlyPath(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if ("id".equals(lower) || "schemas".equals(lower)
                || "groups".equals(lower) || lower.startsWith("groups.") || lower.startsWith("groups[")
                || "meta".equals(lower) || lower.startsWith("meta.")
                || "manager.displayname".equals(lower)
                || (ENTERPRISE_PREFIX.toLowerCase(Locale.ROOT) + ":manager.displayname").equals(lower)
                || (ENTERPRISE_PREFIX.toLowerCase(Locale.ROOT) + ".manager.displayname").equals(lower)) {
            return true;
        }
        return false;
    }

    public static void applyPatchOperations(ScimUser user, List<Map<String, Object>> operations) {
        if (operations == null || operations.isEmpty()) {
            throw new ScimException(400, "invalidSyntax", "PATCH request must contain at least one operation");
        }

        for (Map<String, Object> op : operations) {
            if (op == null) {
                throw new ScimException(400, "invalidSyntax", "PATCH operation must be an object");
            }
            Object rawOp = op.get("op");
            if (!(rawOp instanceof String opStr) || opStr.isBlank()) {
                throw new ScimException(400, "invalidValue", "PATCH operation must include a string 'op' field");
            }
            String opType = opStr.trim().toLowerCase(Locale.ROOT);

            Object rawPath = op.get("path");
            if (rawPath != null && !(rawPath instanceof String)) {
                throw new ScimException(400, "invalidSyntax", "PATCH operation 'path' must be a string");
            }
            String path = stripPathPrefix((String) rawPath);
            Object value = op.get(KEY_VALUE);

            // Validate read-only attributes case-insensitively
            if (path != null && !path.isEmpty() && isReadOnlyPath(path)) {
                throw new ScimException(400, "mutability",
                        "Attribute '" + path + "' is readOnly and cannot be modified");
            }

            switch (opType) {
                case "add" -> applyAdd(user, path, value);
                case "replace" -> applyReplace(user, path, value);
                case "remove" -> applyRemove(user, path);
                default -> throw new ScimException(400, "invalidSyntax", "Unknown PATCH operation: " + opType);
            }
        }
    }

    // ── ADD ─────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static void applyAdd(ScimUser user, String path, Object value) {
        if (value == null) {
            throw new ScimException(400, "invalidValue", "PATCH 'add' operation must contain a 'value' member");
        }
        if (path == null || path.isEmpty()) {
            if (value instanceof Map<?, ?> rawMap) {
                applyValueMap(user, (Map<String, Object>) rawMap);
            } else {
                throw new ScimException(400, "invalidSyntax", "Add without path requires a map value");
            }
            return;
        }

        // Check for filtered path on multi-valued attributes
        Matcher m = FILTERED_PATH.matcher(path);
        if (m.matches()) {
            applyFilteredAdd(user, m.group(1), m.group(2), m.group(3), value);
            return;
        }
        validateUnmatchedBrackets(path);

        // Handle enterprise extension paths
        if (path.equalsIgnoreCase(ENTERPRISE_PREFIX)) {
            setWholeEnterpriseExtension(user, value);
            return;
        }
        if (hasEnterprisePrefix(path)) {
            String entAttr = path.substring(ENTERPRISE_PREFIX.length() + 1);
            setEnterpriseAttribute(user, entAttr, value);
            return;
        }

        if ("name".equalsIgnoreCase(path)) {
            setNameAttribute(user, value);
            return;
        }

        // Handle sub-attribute paths (name.givenName)
        if (path.contains(".")) {
            setSubAttribute(user, path, value);
            return;
        }

        // Multi-valued attributes: add appends
        String canonicalCollection = resolveMultiValuedCollectionName(path);
        if (canonicalCollection != null) {
            addToMultiValued(user, canonicalCollection, value);
            return;
        }

        // Single-valued: add = replace
        setSingleAttribute(user, path, value);
    }

    // ── REPLACE ─────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static void applyReplace(ScimUser user, String path, Object value) {
        if (path == null || path.isEmpty()) {
            if (value instanceof Map<?, ?> rawMap) {
                applyValueMap(user, (Map<String, Object>) rawMap);
            } else {
                throw new ScimException(400, "invalidSyntax", "Replace without path requires a map value");
            }
            return;
        }

        // Filtered path
        Matcher m = FILTERED_PATH.matcher(path);
        if (m.matches()) {
            applyFilteredReplace(user, m.group(1), m.group(2), m.group(3), value);
            return;
        }
        validateUnmatchedBrackets(path);

        // Enterprise extension
        if (path.equalsIgnoreCase(ENTERPRISE_PREFIX)) {
            setWholeEnterpriseExtension(user, value);
            return;
        }
        if (hasEnterprisePrefix(path)) {
            String entAttr = path.substring(ENTERPRISE_PREFIX.length() + 1);
            setEnterpriseAttribute(user, entAttr, value);
            return;
        }

        if ("name".equalsIgnoreCase(path)) {
            setNameAttribute(user, value);
            return;
        }

        // Sub-attribute
        if (path.contains(".")) {
            setSubAttribute(user, path, value);
            return;
        }

        // Multi-valued: replace replaces the entire array
        String canonicalCollection = resolveMultiValuedCollectionName(path);
        if (canonicalCollection != null) {
            if (value == null) {
                clearAttribute(user, canonicalCollection);
            } else if (value instanceof List<?> || value instanceof Map<?, ?>) {
                replaceMultiValued(user, canonicalCollection, value);
            } else {
                throw new ScimException(400, "invalidValue",
                        "Attribute '" + canonicalCollection + "' must be an array");
            }
            return;
        }

        setSingleAttribute(user, path, value);
    }

    // ── REMOVE ──────────────────────────────────────────────

    private static void applyRemove(ScimUser user, String path) {
        if (path == null || path.isEmpty()) {
            throw new ScimException(400, "noTarget", "Remove operation requires a path");
        }

        // Filtered path
        Matcher m = FILTERED_PATH.matcher(path);
        if (m.matches()) {
            applyFilteredRemove(user, m.group(1), m.group(2));
            return;
        }
        validateUnmatchedBrackets(path);

        // Enterprise extension
        if (path.equalsIgnoreCase(ENTERPRISE_PREFIX)) {
            clearEnterpriseExtension(user);
            return;
        }
        if (hasEnterprisePrefix(path)) {
            String entAttr = path.substring(ENTERPRISE_PREFIX.length() + 1);
            setEnterpriseAttribute(user, entAttr, null);
            return;
        }

        // Sub-attribute
        if (path.contains(".")) {
            setSubAttribute(user, path, null);
            return;
        }

        // Full attribute removal
        clearAttribute(user, path);
    }

    private static boolean hasEnterprisePrefix(String path) {
        return path.length() > ENTERPRISE_PREFIX.length() + 1
                && path.regionMatches(true, 0, ENTERPRISE_PREFIX, 0, ENTERPRISE_PREFIX.length())
                && (path.charAt(ENTERPRISE_PREFIX.length()) == ':' || path.charAt(ENTERPRISE_PREFIX.length()) == '.');
    }

    // ── FILTERED OPERATIONS ─────────────────────────────────

    private static void applyFilteredAdd(ScimUser user, String attr, String filter, String subAttr, Object value) {
        applyFilteredReplace(user, attr, filter, subAttr, value);
    }

    private static void validateUnmatchedBrackets(String path) {
        if (path.indexOf('[') >= 0 || path.indexOf(']') >= 0) {
            if (path.contains("[]")) {
                throw new ScimException(400, "invalidFilter", "Empty filter expression in PATCH path: " + path);
            }
            throw new ScimException(400, "invalidPath", "Malformed valuePath in PATCH path: " + path);
        }
    }

    private static FilterNode parsePatchValueFilter(String canonical, String filter) {
        if (filter == null || filter.isBlank()) {
            throw new ScimException(400, "invalidFilter", "Empty filter expression in PATCH path");
        }
        FilterNode ast;
        try {
            ast = ScimFilterParser.parseAst(canonical + "[" + filter + "]", true);
        } catch (ScimException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ScimException(400, "invalidFilter", "Invalid filter in PATCH path: " + e.getMessage(), e);
        }
        if (!(ast instanceof FilterNode.ValuePathNode vp)) {
            throw new ScimException(400, "invalidFilter", "Invalid valuePath filter in PATCH path: " + filter);
        }
        return vp.inner();
    }

    private static void applyFilteredReplace(ScimUser user, String attr, String filter,
                                              String subAttr, Object value) {
        String canonical = resolveMultiValuedCollectionName(attr);
        if (canonical == null) {
            if ("members".equalsIgnoreCase(attr)) {
                throw new ScimException(400, "noTarget", "Use group-specific PATCH for members");
            }
            throw new ScimException(400, "noTarget", "Filtered path not supported for attribute: " + attr);
        }
        FilterNode innerFilter = parsePatchValueFilter(canonical, filter);
        switch (canonical) {
            case ATTR_EMAILS -> {
                applyFilteredUpdate(user.getEmails(), filter,
                        email -> matchesEmailFilter(email, innerFilter),
                        email -> {
                            setEmailSubAttribute(email, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getEmails().forEach(other -> { if (other != email) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_EMAILS);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getEmails(), true);
            }
            case ATTR_PHONE_NUMBERS -> {
                applyFilteredUpdate(user.getPhoneNumbers(), filter,
                        phone -> matchesPhoneFilter(phone, innerFilter),
                        phone -> {
                            setPhoneSubAttribute(phone, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getPhoneNumbers().forEach(other -> { if (other != phone) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_PHONE_NUMBERS);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getPhoneNumbers(), false);
            }
            case ATTR_ADDRESSES -> {
                applyFilteredUpdate(user.getAddresses(), filter,
                        address -> matchesAddressFilter(address, innerFilter),
                        address -> {
                            setAddressSubAttribute(address, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getAddresses().forEach(other -> { if (other != address) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_ADDRESSES);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getAddresses(), false);
            }
            case ATTR_IMS -> {
                applyFilteredUpdate(user.getIms(), filter,
                        im -> matchesImFilter(im, innerFilter),
                        im -> {
                            setImSubAttribute(im, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getIms().forEach(other -> { if (other != im) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_IMS);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getIms(), false);
            }
            case ATTR_PHOTOS -> {
                applyFilteredUpdate(user.getPhotos(), filter,
                        photo -> matchesPhotoFilter(photo, innerFilter),
                        photo -> {
                            setPhotoSubAttribute(photo, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getPhotos().forEach(other -> { if (other != photo) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_PHOTOS);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getPhotos(), false);
            }
            case ATTR_ROLES -> {
                applyFilteredUpdate(user.getRoles(), filter,
                        role -> matchesRoleFilter(role, innerFilter),
                        role -> {
                            setRoleSubAttribute(role, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getRoles().forEach(other -> { if (other != role) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_ROLES);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getRoles(), false);
            }
            case ATTR_ENTITLEMENTS -> {
                applyFilteredUpdate(user.getEntitlements(), filter,
                        entitlement -> matchesEntitlementFilter(entitlement, innerFilter),
                        entitlement -> {
                            setEntitlementSubAttribute(entitlement, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getEntitlements().forEach(other -> { if (other != entitlement) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_ENTITLEMENTS);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getEntitlements(), false);
            }
            case ATTR_X509 -> {
                applyFilteredUpdate(user.getX509Certificates(), filter,
                        cert -> matchesCertFilter(cert, innerFilter),
                        cert -> {
                            setCertSubAttribute(cert, subAttr, value);
                            if (isSettingPrimaryTrue(subAttr, value)) {
                                user.getX509Certificates().forEach(other -> { if (other != cert) other.setPrimaryFlag(false); });
                            }
                        },
                        ATTR_X509);
                ScimUserMapper.deduplicateAndNormalizeCollection(user.getX509Certificates(), false);
            }
            default -> throw new ScimException(400, "noTarget", "Filtered path not supported for attribute: " + attr);
        }
    }

    private static boolean isSettingPrimaryTrue(String subAttr, Object value) {
        if (KEY_PRIMARY.equalsIgnoreCase(subAttr)) {
            return Boolean.TRUE.equals(value);
        }
        if (subAttr == null && value instanceof Map<?, ?> rawMap) {
            return Boolean.TRUE.equals(rawMap.get(KEY_PRIMARY));
        }
        return false;
    }

    private static void applyFilteredRemove(ScimUser user, String attr, String filter) {
        String canonical = resolveMultiValuedCollectionName(attr);
        if (canonical == null) {
            throw new ScimException(400, "noTarget", "Filtered remove not supported for: " + attr);
        }
        FilterNode innerFilter = parsePatchValueFilter(canonical, filter);
        switch (canonical) {
            case ATTR_EMAILS -> user.getEmails().removeIf(email -> matchesEmailFilter(email, innerFilter));
            case ATTR_PHONE_NUMBERS -> user.getPhoneNumbers().removeIf(phone -> matchesPhoneFilter(phone, innerFilter));
            case ATTR_ADDRESSES -> user.getAddresses().removeIf(addr -> matchesAddressFilter(addr, innerFilter));
            case ATTR_ROLES -> user.getRoles().removeIf(role -> matchesRoleFilter(role, innerFilter));
            case ATTR_ENTITLEMENTS -> user.getEntitlements().removeIf(ent -> matchesEntitlementFilter(ent, innerFilter));
            case ATTR_IMS -> user.getIms().removeIf(im -> matchesImFilter(im, innerFilter));
            case ATTR_PHOTOS -> user.getPhotos().removeIf(photo -> matchesPhotoFilter(photo, innerFilter));
            case ATTR_X509 -> user.getX509Certificates().removeIf(cert -> matchesCertFilter(cert, innerFilter));
            default -> throw new ScimException(400, "noTarget", "Filtered remove not supported for: " + attr);
        }
    }

    // ── FILTER MATCHING ─────────────────────────────────────

    private static boolean matchesEmailFilter(ScimUserEmail email, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        email.getValue(), email.getType(), email.isPrimaryFlag(), email.getDisplay(), null),
                ATTR_EMAILS, innerFilter);
    }

    private static boolean matchesPhoneFilter(ScimUserPhoneNumber phone, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        phone.getValue(), phone.getType(), phone.isPrimaryFlag(), phone.getDisplay(), null),
                ATTR_PHONE_NUMBERS, innerFilter);
    }

    private static boolean matchesAddressFilter(ScimUserAddress addr, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toAddressElementMap(addr),
                ATTR_ADDRESSES, innerFilter);
    }

    private static boolean matchesRoleFilter(ScimUserRole role, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        role.getValue(), role.getType(), role.isPrimaryFlag(), role.getDisplay(), null),
                ATTR_ROLES, innerFilter);
    }

    private static boolean matchesEntitlementFilter(ScimUserEntitlement ent, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        ent.getValue(), ent.getType(), ent.isPrimaryFlag(), ent.getDisplay(), null),
                ATTR_ENTITLEMENTS, innerFilter);
    }

    private static boolean matchesImFilter(ScimUserIm im, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        im.getValue(), im.getType(), im.isPrimaryFlag(), im.getDisplay(), null),
                ATTR_IMS, innerFilter);
    }

    private static boolean matchesPhotoFilter(ScimUserPhoto photo, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        photo.getValue(), photo.getType(), photo.isPrimaryFlag(), photo.getDisplay(), photo.getValue()),
                ATTR_PHOTOS, innerFilter);
    }

    private static boolean matchesCertFilter(ScimUserX509Certificate cert, FilterNode innerFilter) {
        return ScimFilterEvaluator.matchesCollectionElement(
                ScimFilterEvaluator.toStandardElementMap(
                        cert.getValue(), cert.getType(), cert.isPrimaryFlag(), cert.getDisplay(), null),
                ATTR_X509, innerFilter);
    }

    // ── ATTRIBUTE SETTERS ───────────────────────────────────

    private static void setSingleAttribute(ScimUser user, String attr, Object value) {
        String lower = attr.toLowerCase(Locale.ROOT);
        switch (lower) {
            case "username" -> user.setUserName(ScimCanonicalizer.requireNullableString(value, "userName"));
            case "externalid" -> user.setExternalId(ScimCanonicalizer.requireNullableString(value, "externalId"));
            case "displayname" -> user.setDisplayName(ScimCanonicalizer.requireNullableString(value, KEY_DISPLAY_NAME));
            case "nickname" -> user.setNickName(ScimCanonicalizer.requireNullableString(value, "nickName"));
            case "profileurl" -> user.setProfileUrl(ScimCanonicalizer.requireNullableString(value, "profileUrl"));
            case "title" -> user.setTitle(ScimCanonicalizer.requireNullableString(value, "title"));
            case "usertype" -> user.setUserType(ScimCanonicalizer.requireNullableString(value, "userType"));
            case "preferredlanguage" -> user.setPreferredLanguage(ScimCanonicalizer.requireNullableString(value, "preferredLanguage"));
            case "locale" -> user.setLocale(ScimCanonicalizer.requireNullableString(value, "locale"));
            case "timezone" -> user.setTimezone(ScimCanonicalizer.requireNullableString(value, "timezone"));
            case "active" -> user.setActive(ScimCanonicalizer.requireBoolean(value, "active", true));
            case "password" -> user.setPassword(ScimUserMapper.hashPassword(ScimCanonicalizer.requireNullableString(value, "password")));
            default -> throw new ScimException(400, "noTarget", "Unknown attribute: " + attr);
        }
    }

    private static void setSubAttribute(ScimUser user, String path, Object value) {
        String[] parts = path.split("\\.", 2);
        String parent = parts[0];
        String sub = parts[1];

        if ("name".equalsIgnoreCase(parent)) {
            switch (sub.toLowerCase(Locale.ROOT)) {
                case "formatted" -> user.setNameFormatted(ScimCanonicalizer.requireNullableString(value, "name.formatted"));
                case "familyname" -> user.setNameFamilyName(ScimCanonicalizer.requireNullableString(value, "name.familyName"));
                case "givenname" -> user.setNameGivenName(ScimCanonicalizer.requireNullableString(value, "name.givenName"));
                case "middlename" -> user.setNameMiddleName(ScimCanonicalizer.requireNullableString(value, "name.middleName"));
                case "honorificprefix" -> user.setNameHonorificPrefix(ScimCanonicalizer.requireNullableString(value, "name.honorificPrefix"));
                case "honorificsuffix" -> user.setNameHonorificSuffix(ScimCanonicalizer.requireNullableString(value, "name.honorificSuffix"));
                default -> throw new ScimException(400, "noTarget", "Unknown name sub-attribute: " + sub);
            }
        } else {
            throw new ScimException(400, "noTarget", "Unknown complex attribute: " + parent);
        }
    }

    @SuppressWarnings("unchecked")
    private static void setNameAttribute(ScimUser user, Object value) {
        if (value == null) {
            clearAttribute(user, "name");
            return;
        }
        if (!(value instanceof Map<?, ?> rawMap)) {
            throw new ScimException(400, "invalidValue", "Attribute 'name' must be an object");
        }
        Map<String, Object> nameMap = (Map<String, Object>) rawMap;
        for (Map.Entry<String, Object> entry : nameMap.entrySet()) {
            String sub = entry.getKey();
            Object val = entry.getValue();
            switch (sub.toLowerCase(Locale.ROOT)) {
                case "formatted" -> user.setNameFormatted(ScimCanonicalizer.requireNullableString(val, "name.formatted"));
                case "familyname" -> user.setNameFamilyName(ScimCanonicalizer.requireNullableString(val, "name.familyName"));
                case "givenname" -> user.setNameGivenName(ScimCanonicalizer.requireNullableString(val, "name.givenName"));
                case "middlename" -> user.setNameMiddleName(ScimCanonicalizer.requireNullableString(val, "name.middleName"));
                case "honorificprefix" -> user.setNameHonorificPrefix(ScimCanonicalizer.requireNullableString(val, "name.honorificPrefix"));
                case "honorificsuffix" -> user.setNameHonorificSuffix(ScimCanonicalizer.requireNullableString(val, "name.honorificSuffix"));
                default -> throw new ScimException(400, "noTarget", "Unknown name sub-attribute: " + sub);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void setWholeEnterpriseExtension(ScimUser user, Object value) {
        if (value == null) {
            clearEnterpriseExtension(user);
            return;
        }
        if (!(value instanceof Map<?, ?> rawMap)) {
            throw new ScimException(400, "invalidValue", "Enterprise extension must be an object");
        }
        applyEnterpriseMapEntries(user, (Map<String, Object>) rawMap);
    }

    private static void applyEnterpriseMapEntries(ScimUser user, Map<String, Object> entries) {
        boolean hasMgrObj = false;
        Object mgrObj = null;
        boolean hasMgrVal = false;
        Object mgrVal = null;
        boolean hasMgrRef = false;
        Object mgrRef = null;

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            String kLower = entry.getKey().toLowerCase(Locale.ROOT);
            switch (kLower) {
                case "manager" -> {
                    hasMgrObj = true;
                    mgrObj = entry.getValue();
                }
                case "manager.value" -> {
                    hasMgrVal = true;
                    mgrVal = entry.getValue();
                }
                case "manager.$ref" -> {
                    hasMgrRef = true;
                    mgrRef = entry.getValue();
                }
                default -> setEnterpriseAttribute(user, entry.getKey(), entry.getValue());
            }
        }

        int mgrFieldCount = (hasMgrObj ? 1 : 0) + (hasMgrVal ? 1 : 0) + (hasMgrRef ? 1 : 0);
        if (mgrFieldCount == 1) {
            if (hasMgrObj) {
                setEnterpriseAttribute(user, "manager", mgrObj);
            } else if (hasMgrVal) {
                setEnterpriseAttribute(user, "manager.value", mgrVal);
            } else {
                setEnterpriseAttribute(user, "manager.$ref", mgrRef);
            }
        } else if (mgrFieldCount > 1) {
            Map<String, Object> combined = new LinkedHashMap<>();
            if (hasMgrObj) {
                if (mgrObj instanceof Map<?, ?> mMap) {
                    mMap.forEach((k, v) -> combined.put(String.valueOf(k), v));
                } else if (mgrObj instanceof String || mgrObj == null) {
                    combined.put(KEY_VALUE, mgrObj);
                } else {
                    throw new ScimException(400, "invalidValue", "Enterprise manager must be a complex object or string");
                }
            }
            if (hasMgrVal) {
                if (combined.containsKey(KEY_VALUE) && !Objects.equals(combined.get(KEY_VALUE), mgrVal)) {
                    throw new ScimException(400, "invalidValue", "Conflicting manager 'value' definitions in PATCH");
                }
                combined.put(KEY_VALUE, mgrVal);
            }
            if (hasMgrRef) {
                if (combined.containsKey("$ref") && !Objects.equals(combined.get("$ref"), mgrRef)) {
                    throw new ScimException(400, "invalidValue", "Conflicting manager '$ref' definitions in PATCH");
                }
                combined.put("$ref", mgrRef);
            }
            ScimUserMapper.applyEnterpriseManager(user, combined);
        }
    }

    private static void clearEnterpriseExtension(ScimUser user) {
        user.setEnterpriseEmployeeNumber(null);
        user.setEnterpriseCostCenter(null);
        user.setEnterpriseOrganization(null);
        user.setEnterpriseDivision(null);
        user.setEnterpriseDepartment(null);
        user.setEnterpriseManagerValue(null);
        user.setEnterpriseManagerRef(null);
        user.setEnterpriseManagerDisplay(null);
    }

    private static void setEnterpriseAttribute(ScimUser user, String attr, Object value) {
        String lower = attr.toLowerCase(Locale.ROOT);
        switch (lower) {
            case "employeenumber" -> user.setEnterpriseEmployeeNumber(ScimCanonicalizer.requireNullableString(value, "employeeNumber"));
            case "costcenter" -> user.setEnterpriseCostCenter(ScimCanonicalizer.requireNullableString(value, "costCenter"));
            case "organization" -> user.setEnterpriseOrganization(ScimCanonicalizer.requireNullableString(value, "organization"));
            case "division" -> user.setEnterpriseDivision(ScimCanonicalizer.requireNullableString(value, "division"));
            case "department" -> user.setEnterpriseDepartment(ScimCanonicalizer.requireNullableString(value, "department"));
            case "manager" -> setEnterpriseManager(user, value);
            case "manager.value" -> {
                String v = ScimCanonicalizer.requireNullableString(value, "manager.value");
                if (v == null || v.isBlank()) {
                    user.setEnterpriseManagerValue(null);
                    user.setEnterpriseManagerRef(null);
                    user.setEnterpriseManagerDisplay(null);
                } else {
                    user.setEnterpriseManagerValue(
                            ScimUserMapper.canonicalizeManagerIdentifier(ScimCanonicalizer.normalizeNfc(v.trim())));
                    user.setEnterpriseManagerRef(null);
                    user.setEnterpriseManagerDisplay(null);
                }
            }
            case "manager.$ref" -> {
                String ref = ScimCanonicalizer.requireNullableString(value, "manager.$ref");
                if (ref == null || ref.isBlank()) {
                    user.setEnterpriseManagerRef(null);
                } else {
                    String trimmedRef = ref.trim();
                    String refUserId = ScimUserMapper.extractAndValidateManagerUserIdFromRef(
                            trimmedRef, "enterprise.manager.$ref");
                    if (!Objects.equals(user.getEnterpriseManagerValue(), refUserId)) {
                        user.setEnterpriseManagerValue(refUserId);
                        user.setEnterpriseManagerDisplay(null);
                    }
                    user.setEnterpriseManagerRef(trimmedRef);
                }
            }
            case "manager.displayname" -> throw new ScimException(400, "mutability",
                    "Attribute 'manager.displayName' is readOnly and cannot be modified");
            default -> throw new ScimException(400, "noTarget", "Unknown enterprise attribute: " + attr);
        }
    }

    private static void setEnterpriseManager(ScimUser user, Object value) {
        ScimUserMapper.applyEnterpriseManager(user, value);
    }

    private static void applyValueMap(ScimUser user, Map<String, Object> valueMap) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        Map<String, Object> dottedEnterpriseAttrs = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : valueMap.entrySet()) {
            String rawKey = entry.getKey();
            Object val = entry.getValue();
            String key = stripPathPrefix(rawKey);
            String keyLower = key.toLowerCase(Locale.ROOT);

            // Ignore echoed readOnly/schema metadata in pathless add/replace; reject groups modification
            if ("id".equals(keyLower) || "schemas".equals(keyLower) || "meta".equals(keyLower)) {
                continue;
            }
            if ("groups".equals(keyLower)) {
                throw new ScimException(400, "mutability", "Attribute 'groups' is readOnly and cannot be modified");
            }

            if (key.equalsIgnoreCase(ENTERPRISE_PREFIX)) {
                setWholeEnterpriseExtension(user, val);
            } else if (hasEnterprisePrefix(key)) {
                String entAttr = key.substring(ENTERPRISE_PREFIX.length() + 1);
                dottedEnterpriseAttrs.put(entAttr, val);
            } else if (key.contains(".")) {
                if (isReadOnlyPath(key)) {
                    throw new ScimException(400, "mutability", "Attribute '" + key + "' is readOnly and cannot be modified");
                }
                setSubAttribute(user, key, val);
            } else {
                normalized.put(key, val);
            }
        }

        if (!dottedEnterpriseAttrs.isEmpty()) {
            applyEnterpriseMapEntries(user, dottedEnterpriseAttrs);
        }

        if (!normalized.isEmpty()) {
            ScimUserMapper.applyFromScimInput(user, normalized);
        }
    }

    @SuppressWarnings("unchecked")
    private static void addToMultiValued(ScimUser user, String attr, Object value) {
        List<Map<String, Object>> items;
        if (value instanceof List<?> rawList) {
            items = new ArrayList<>(rawList.size());
            for (Object elem : rawList) {
                if (!(elem instanceof Map<?, ?> elemMap)) {
                    throw new ScimException(400, "invalidValue", "Elements of '" + attr + "' must be complex objects");
                }
                items.add((Map<String, Object>) elemMap);
            }
        } else if (value instanceof Map<?, ?> rawMap) {
            items = List.of((Map<String, Object>) rawMap);
        } else {
            throw new ScimException(400, "invalidSyntax", "Add to multi-valued requires array or object value");
        }

        switch (attr) {
            case ATTR_EMAILS -> addItems(items, user.getEmails(), ScimUserMapper::buildEmail, true);
            case ATTR_PHONE_NUMBERS -> addItems(items, user.getPhoneNumbers(), ScimUserMapper::buildPhone, false);
            case ATTR_ADDRESSES -> addItems(items, user.getAddresses(), ScimUserMapper::buildAddress, false);
            case ATTR_IMS -> addItems(items, user.getIms(), ScimUserMapper::buildIm, false);
            case ATTR_PHOTOS -> addItems(items, user.getPhotos(), ScimUserMapper::buildPhoto, false);
            case ATTR_ROLES -> addItems(items, user.getRoles(), ScimUserMapper::buildRole, false);
            case ATTR_ENTITLEMENTS -> addItems(items, user.getEntitlements(), ScimUserMapper::buildEntitlement, false);
            case ATTR_X509 -> addItems(items, user.getX509Certificates(), ScimUserMapper::buildCertificate, false);
            default -> throw new ScimException(400, "noTarget", "Cannot add to attribute: " + attr);
        }
    }

    private static void replaceMultiValued(ScimUser user, String attr, Object value) {
        clearAttribute(user, attr);
        addToMultiValued(user, attr, value);
    }

    private static void clearAttribute(ScimUser user, String attr) {
        String lower = attr.toLowerCase(Locale.ROOT);
        switch (lower) {
            case "username" -> throw new ScimException(400, "mutability",
                    "Required attribute 'userName' cannot be removed");
            case "externalid" -> user.setExternalId(null);
            case "displayname" -> user.setDisplayName(null);
            case "nickname" -> user.setNickName(null);
            case "profileurl" -> user.setProfileUrl(null);
            case "title" -> user.setTitle(null);
            case "usertype" -> user.setUserType(null);
            case "preferredlanguage" -> user.setPreferredLanguage(null);
            case "locale" -> user.setLocale(null);
            case "timezone" -> user.setTimezone(null);
            case "name" -> {
                user.setNameFormatted(null);
                user.setNameFamilyName(null);
                user.setNameGivenName(null);
                user.setNameMiddleName(null);
                user.setNameHonorificPrefix(null);
                user.setNameHonorificSuffix(null);
            }
            case "emails" -> user.getEmails().clear();
            case "phonenumbers" -> user.getPhoneNumbers().clear();
            case "addresses" -> user.getAddresses().clear();
            case "ims" -> user.getIms().clear();
            case "photos" -> user.getPhotos().clear();
            case "entitlements" -> user.getEntitlements().clear();
            case "roles" -> user.getRoles().clear();
            case "x509certificates" -> user.getX509Certificates().clear();
            default -> throw new ScimException(400, "noTarget", "Cannot remove attribute: " + attr);
        }
    }

    private static void setEmailSubAttribute(ScimUserEmail email, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Email element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setEmailSubAttribute(email, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setEmailSubAttribute(email, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setEmailSubAttribute(email, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setEmailSubAttribute(email, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> email.setValue(ScimCanonicalizer.canonicalizeEmail(
                    ScimCanonicalizer.requireNullableString(value, "emails.value")));
            case "type" -> email.setType(ScimCanonicalizer.canonicalizeType(value, EMAIL_TYPES, null, "emails.type"));
            case "display" -> email.setDisplay(ScimCanonicalizer.requireNullableString(value, "emails.display"));
            case "primary" -> email.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "emails.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown email sub-attribute: " + subAttr);
        }
    }

    private static void setPhoneSubAttribute(ScimUserPhoneNumber phone, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Phone element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setPhoneSubAttribute(phone, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setPhoneSubAttribute(phone, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setPhoneSubAttribute(phone, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setPhoneSubAttribute(phone, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> phone.setValue(ScimCanonicalizer.canonicalizePhoneNumber(
                    ScimCanonicalizer.requireNullableString(value, "phoneNumbers.value")));
            case "type" -> phone.setType(ScimCanonicalizer.canonicalizeType(value, PHONE_TYPES, null, "phoneNumbers.type"));
            case "display" -> phone.setDisplay(ScimCanonicalizer.requireNullableString(value, "phoneNumbers.display"));
            case "primary" -> phone.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "phoneNumbers.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown phone sub-attribute: " + subAttr);
        }
    }

    private static void setAddressSubAttribute(ScimUserAddress address, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Address element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_FORMATTED)) setAddressSubAttribute(address, KEY_FORMATTED, rawMap.get(KEY_FORMATTED));
            if (rawMap.containsKey("streetAddress")) setAddressSubAttribute(address, "streetAddress", rawMap.get("streetAddress"));
            if (rawMap.containsKey("locality")) setAddressSubAttribute(address, "locality", rawMap.get("locality"));
            if (rawMap.containsKey("region")) setAddressSubAttribute(address, "region", rawMap.get("region"));
            if (rawMap.containsKey("postalCode")) setAddressSubAttribute(address, "postalCode", rawMap.get("postalCode"));
            if (rawMap.containsKey("country")) setAddressSubAttribute(address, "country", rawMap.get("country"));
            if (rawMap.containsKey(KEY_TYPE)) setAddressSubAttribute(address, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_PRIMARY)) setAddressSubAttribute(address, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "formatted" -> address.setFormatted(ScimCanonicalizer.requireNullableString(value, "addresses.formatted"));
            case "streetaddress" -> address.setStreetAddress(ScimCanonicalizer.requireNullableString(value, "addresses.streetAddress"));
            case "locality" -> address.setLocality(ScimCanonicalizer.requireNullableString(value, "addresses.locality"));
            case "region" -> address.setRegion(ScimCanonicalizer.requireNullableString(value, "addresses.region"));
            case "postalcode" -> address.setPostalCode(ScimCanonicalizer.requireNullableString(value, "addresses.postalCode"));
            case "country" -> address.setCountry(ScimUserMapper.normalizeCountry(
                    ScimCanonicalizer.requireNullableString(value, "addresses.country")));
            case "type" -> address.setType(ScimCanonicalizer.canonicalizeType(value, ADDRESS_TYPES, null, "addresses.type"));
            case "primary" -> address.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "addresses.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown address sub-attribute: " + subAttr);
        }
    }

    private static void setImSubAttribute(ScimUserIm im, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "IM element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setImSubAttribute(im, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setImSubAttribute(im, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setImSubAttribute(im, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setImSubAttribute(im, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> im.setValue(ScimCanonicalizer.canonicalizeIm(
                    ScimCanonicalizer.requireNullableString(value, "ims.value")));
            case "type" -> im.setType(ScimCanonicalizer.canonicalizeType(value, IM_TYPES, null, "ims.type"));
            case "display" -> im.setDisplay(ScimCanonicalizer.requireNullableString(value, "ims.display"));
            case "primary" -> im.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "ims.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown ims sub-attribute: " + subAttr);
        }
    }

    private static void setPhotoSubAttribute(ScimUserPhoto photo, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Photo element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setPhotoSubAttribute(photo, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setPhotoSubAttribute(photo, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setPhotoSubAttribute(photo, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setPhotoSubAttribute(photo, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> photo.setValue(ScimCanonicalizer.requireNullableString(value, "photos.value"));
            case "type" -> photo.setType(ScimCanonicalizer.canonicalizeType(value, PHOTO_TYPES, null, "photos.type"));
            case "display" -> photo.setDisplay(ScimCanonicalizer.requireNullableString(value, "photos.display"));
            case "primary" -> photo.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "photos.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown photos sub-attribute: " + subAttr);
        }
    }

    private static void setRoleSubAttribute(ScimUserRole role, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Role element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setRoleSubAttribute(role, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setRoleSubAttribute(role, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setRoleSubAttribute(role, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setRoleSubAttribute(role, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> role.setValue(ScimCanonicalizer.requireNullableString(value, "roles.value"));
            case "type" -> role.setType(ScimCanonicalizer.canonicalizeType(value, null, null, "roles.type"));
            case "display" -> role.setDisplay(ScimCanonicalizer.requireNullableString(value, "roles.display"));
            case "primary" -> role.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "roles.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown role sub-attribute: " + subAttr);
        }
    }

    private static void setEntitlementSubAttribute(ScimUserEntitlement ent, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Entitlement element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setEntitlementSubAttribute(ent, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setEntitlementSubAttribute(ent, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setEntitlementSubAttribute(ent, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setEntitlementSubAttribute(ent, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> ent.setValue(ScimCanonicalizer.requireNullableString(value, "entitlements.value"));
            case "type" -> ent.setType(ScimCanonicalizer.canonicalizeType(value, null, null, "entitlements.type"));
            case "display" -> ent.setDisplay(ScimCanonicalizer.requireNullableString(value, "entitlements.display"));
            case "primary" -> ent.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "entitlements.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown entitlements sub-attribute: " + subAttr);
        }
    }

    private static void setCertSubAttribute(ScimUserX509Certificate cert, String subAttr, Object value) {
        if (subAttr == null) {
            if (!(value instanceof Map<?, ?> rawMap)) {
                throw new ScimException(400, "invalidValue", "Certificate element replacement requires an object");
            }
            if (rawMap.containsKey(KEY_VALUE)) setCertSubAttribute(cert, KEY_VALUE, rawMap.get(KEY_VALUE));
            if (rawMap.containsKey(KEY_TYPE)) setCertSubAttribute(cert, KEY_TYPE, rawMap.get(KEY_TYPE));
            if (rawMap.containsKey(KEY_DISPLAY)) setCertSubAttribute(cert, KEY_DISPLAY, rawMap.get(KEY_DISPLAY));
            if (rawMap.containsKey(KEY_PRIMARY)) setCertSubAttribute(cert, KEY_PRIMARY, rawMap.get(KEY_PRIMARY));
            return;
        }
        switch (subAttr.toLowerCase(Locale.ROOT)) {
            case "value" -> {
                String binary = ScimCanonicalizer.requireNullableString(value, "x509Certificates.value");
                if (binary != null) {
                    ScimCertificateValidator.validateSingleDerCertificateOrBinary(binary, "x509Certificates.value");
                    cert.setValue(binary.trim());
                } else {
                    cert.setValue(null);
                }
            }
            case "type" -> cert.setType(ScimCanonicalizer.canonicalizeType(value, null, null, "x509Certificates.type"));
            case "display" -> cert.setDisplay(ScimCanonicalizer.requireNullableString(value, "x509Certificates.display"));
            case "primary" -> cert.setPrimaryFlag(ScimCanonicalizer.requireBoolean(value, "x509Certificates.primary", false));
            default -> throw new ScimException(400, "noTarget", "Unknown x509Certificates sub-attribute: " + subAttr);
        }
    }

    private static <T> void applyFilteredUpdate(List<T> collection, String filter,
                                                Predicate<T> matcher,
                                                Consumer<T> action,
                                                String attributeName) {
        boolean found = false;
        for (T item : collection) {
            if (!matcher.test(item)) {
                continue;
            }
            action.accept(item);
            found = true;
        }
        if (!found) {
            throw new ScimException(400, "noTarget", "No " + attributeName + " match filter: " + filter);
        }
    }

    private static <T> void addItems(List<Map<String, Object>> items, List<T> target,
                                     java.util.function.Function<Map<String, Object>, T> mapper,
                                     boolean caseInsensitive) {
        ScimUserMapper.addAndNormalizeItems(items, target, mapper, caseInsensitive);
    }

    // ── MULTI-VALUED CHECK ──────────────────────────────────

    private static String resolveMultiValuedCollectionName(String attr) {
        if (attr == null) return null;
        return switch (attr.toLowerCase(Locale.ROOT)) {
            case "emails" -> ATTR_EMAILS;
            case "phonenumbers" -> ATTR_PHONE_NUMBERS;
            case "addresses" -> ATTR_ADDRESSES;
            case "ims" -> ATTR_IMS;
            case "photos" -> ATTR_PHOTOS;
            case "entitlements" -> ATTR_ENTITLEMENTS;
            case "roles" -> ATTR_ROLES;
            case "x509certificates" -> ATTR_X509;
            default -> null;
        };
    }
}
