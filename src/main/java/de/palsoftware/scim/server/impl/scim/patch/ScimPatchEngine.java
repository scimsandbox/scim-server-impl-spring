package de.palsoftware.scim.server.impl.scim.patch;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.mapper.ScimUserMapper;
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
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.function.Consumer;

/**
 * SCIM PATCH operation engine per RFC 7644 §3.5.2.
 * Supports add, replace, remove operations with path filters.
 */
public class ScimPatchEngine {

    private ScimPatchEngine() {
        /* Utility class */
    }

    private static final String ENTERPRISE_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    // Pattern: attrName[filterExpr].subAttr
    private static final Pattern FILTERED_PATH = Pattern.compile("^(\\w+)\\[(.+)](?:\\.(\\w+))?$");

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

    // Read-only attributes that cannot be modified via PATCH
    private static final Set<String> READ_ONLY_ATTRS = Set.of(
            "id", "meta", "meta.created", "meta.lastModified", "meta.location",
            "meta.resourceType", "meta.version", "groups"
    );

        private static final Set<String> EMAIL_TYPES = Set.of("work", "home", VALUE_OTHER);
        private static final Set<String> PHONE_TYPES = Set.of("work", "home", "mobile", "fax", "pager", VALUE_OTHER);
        private static final Set<String> IM_TYPES = Set.of("aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo");
        private static final Set<String> PHOTO_TYPES = Set.of("photo", "thumbnail");
        private static final Set<String> ADDRESS_TYPES = Set.of("work", "home", VALUE_OTHER);

    public static void applyPatchOperations(ScimUser user, List<Map<String, Object>> operations) {
        if (operations == null || operations.isEmpty()) {
            throw new ScimException(400, "invalidSyntax", "PATCH request must contain at least one operation");
        }

        for (Map<String, Object> op : operations) {
            Object rawOp = op.get("op");
            if (!(rawOp instanceof String)) {
                throw new ScimException(400, "invalidValue", "PATCH operation must include a string 'op' field");
            }
            String opType = ((String) rawOp).toLowerCase();
            String path = (String) op.get("path");
            Object value = op.get(KEY_VALUE);

            // Validate read-only
            if (path != null && READ_ONLY_ATTRS.contains(path)) {
                throw new ScimException(400, "mutability", "Attribute '" + path + "' is readOnly and cannot be modified");
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
        if (path == null || path.isEmpty()) {
            // No path → merge the value as a map into the resource
            if (value instanceof Map) {
                applyValueMap(user, (Map<String, Object>) value);
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

        // Handle enterprise extension paths
        if (path.startsWith(ENTERPRISE_PREFIX + ":")) {
            String entAttr = path.substring(ENTERPRISE_PREFIX.length() + 1);
            setEnterpriseAttribute(user, entAttr, value);
            return;
        }

        // Handle sub-attribute paths (name.givenName)
        if (path.contains(".")) {
            setSubAttribute(user, path, value);
            return;
        }

        // Multi-valued attributes: add appends
        if (isMultiValuedAttribute(path)) {
            addToMultiValued(user, path, value);
            return;
        }

        // Single-valued: add = replace
        setSingleAttribute(user, path, value);
    }

    // ── REPLACE ─────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static void applyReplace(ScimUser user, String path, Object value) {
        if (path == null || path.isEmpty()) {
            // No path → merge
            if (value instanceof Map) {
                applyValueMap(user, (Map<String, Object>) value);
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

        // Enterprise extension
        if (path.startsWith(ENTERPRISE_PREFIX + ":")) {
            String entAttr = path.substring(ENTERPRISE_PREFIX.length() + 1);
            setEnterpriseAttribute(user, entAttr, value);
            return;
        }

        // Sub-attribute
        if (path.contains(".")) {
            setSubAttribute(user, path, value);
            return;
        }

        // Multi-valued: replace replaces the entire array
        if (isMultiValuedAttribute(path) && value instanceof List) {
            replaceMultiValued(user, path, value);
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

        // Enterprise extension
        if (path.startsWith(ENTERPRISE_PREFIX + ":")) {
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

    // ── FILTERED OPERATIONS ─────────────────────────────────

    private static void applyFilteredAdd(ScimUser user, String attr, String filter, String subAttr, Object value) {
        applyFilteredReplace(user, attr, filter, subAttr, value);
    }

    private static void applyFilteredReplace(ScimUser user, String attr, String filter,
                                              String subAttr, Object value) {
        switch (attr) {
                case ATTR_EMAILS -> applyFilteredUpdate(user.getEmails(), filter,
                    email -> matchesFilter(email, filter),
                    email -> setEmailSubAttribute(email, subAttr, value),
                    ATTR_EMAILS);
            case ATTR_PHONE_NUMBERS -> applyFilteredUpdate(user.getPhoneNumbers(), filter,
                    phone -> matchesPhoneFilter(phone, filter),
                    phone -> setPhoneSubAttribute(phone, subAttr, value),
                    ATTR_PHONE_NUMBERS);
            case ATTR_ADDRESSES -> applyFilteredUpdate(user.getAddresses(), filter,
                    address -> matchesAddressFilter(address, filter),
                    address -> setAddressSubAttribute(address, subAttr, value),
                    ATTR_ADDRESSES);
            case ATTR_IMS -> applyFilteredUpdate(user.getIms(), filter,
                    im -> matchesImFilter(im, filter),
                    im -> setImSubAttribute(im, subAttr, value),
                    ATTR_IMS);
            case ATTR_PHOTOS -> applyFilteredUpdate(user.getPhotos(), filter,
                    photo -> matchesPhotoFilter(photo, filter),
                    photo -> setPhotoSubAttribute(photo, subAttr, value),
                    ATTR_PHOTOS);
            case ATTR_ROLES -> applyFilteredUpdate(user.getRoles(), filter,
                    role -> matchesRoleFilter(role, filter),
                    role -> setRoleSubAttribute(role, subAttr, value),
                    ATTR_ROLES);
            case ATTR_ENTITLEMENTS -> applyFilteredUpdate(user.getEntitlements(), filter,
                    entitlement -> matchesEntitlementFilter(entitlement, filter),
                    entitlement -> setEntitlementSubAttribute(entitlement, subAttr, value),
                    ATTR_ENTITLEMENTS);
            case ATTR_X509 -> applyFilteredUpdate(user.getX509Certificates(), filter,
                    cert -> matchesCertFilter(cert, filter),
                    cert -> setCertSubAttribute(cert, subAttr, value),
                    ATTR_X509);
            case "members" -> throw new ScimException(400, "noTarget", "Use group-specific PATCH for members");
            default -> throw new ScimException(400, "noTarget", "Filtered path not supported for attribute: " + attr);
        }
    }

    private static void applyFilteredRemove(ScimUser user, String attr, String filter) {
        if (ATTR_EMAILS.equals(attr)) {
            user.getEmails().removeIf(email -> matchesFilter(email, filter));
        } else if (ATTR_PHONE_NUMBERS.equals(attr)) {
            user.getPhoneNumbers().removeIf(phone -> matchesPhoneFilter(phone, filter));
        } else if (ATTR_ADDRESSES.equals(attr)) {
            user.getAddresses().removeIf(addr -> matchesAddressFilter(addr, filter));
        } else if (ATTR_ROLES.equals(attr)) {
            user.getRoles().removeIf(role -> matchesRoleFilter(role, filter));
        } else if (ATTR_ENTITLEMENTS.equals(attr)) {
            user.getEntitlements().removeIf(ent -> matchesEntitlementFilter(ent, filter));
        } else if (ATTR_IMS.equals(attr)) {
            user.getIms().removeIf(im -> matchesImFilter(im, filter));
        } else if (ATTR_PHOTOS.equals(attr)) {
            user.getPhotos().removeIf(photo -> matchesPhotoFilter(photo, filter));
        } else if (ATTR_X509.equals(attr)) {
            user.getX509Certificates().removeIf(cert -> matchesCertFilter(cert, filter));
        } else {
            throw new ScimException(400, "noTarget", "Filtered remove not supported for: " + attr);
        }
    }

    // ── FILTER MATCHING ─────────────────────────────────────

    private static boolean matchesFilter(ScimUserEmail email, String filter) {
        return matchesGenericFilter(filter,
                Map.of(KEY_VALUE, email.getValue() != null ? email.getValue() : "",
                       KEY_TYPE, email.getType() != null ? email.getType() : "",
                       KEY_PRIMARY, String.valueOf(email.isPrimaryFlag())));
    }

    private static boolean matchesPhoneFilter(ScimUserPhoneNumber phone, String filter) {
        return matchesGenericFilter(filter,
                Map.of(KEY_VALUE, phone.getValue() != null ? phone.getValue() : "",
                       KEY_TYPE, phone.getType() != null ? phone.getType() : "",
                       KEY_PRIMARY, String.valueOf(phone.isPrimaryFlag())));
    }

    private static boolean matchesAddressFilter(ScimUserAddress addr, String filter) {
        return matchesGenericFilter(filter,
                Map.of(KEY_TYPE, addr.getType() != null ? addr.getType() : "",
                       KEY_PRIMARY, String.valueOf(addr.isPrimaryFlag())));
    }

    private static boolean matchesRoleFilter(ScimUserRole role, String filter) {
        return matchesGenericFilter(filter,
              Map.of(KEY_VALUE, role.getValue() != null ? role.getValue() : "",
                  KEY_TYPE, role.getType() != null ? role.getType() : "",
                  KEY_PRIMARY, String.valueOf(role.isPrimaryFlag())));
    }

    private static boolean matchesEntitlementFilter(ScimUserEntitlement ent, String filter) {
        return matchesGenericFilter(filter,
              Map.of(KEY_VALUE, ent.getValue() != null ? ent.getValue() : "",
                  KEY_TYPE, ent.getType() != null ? ent.getType() : "",
                  KEY_PRIMARY, String.valueOf(ent.isPrimaryFlag())));
    }

    private static boolean matchesImFilter(ScimUserIm im, String filter) {
        return matchesGenericFilter(filter,
              Map.of(KEY_VALUE, im.getValue() != null ? im.getValue() : "",
                  KEY_TYPE, im.getType() != null ? im.getType() : "",
                  KEY_PRIMARY, String.valueOf(im.isPrimaryFlag())));
    }

    private static boolean matchesPhotoFilter(ScimUserPhoto photo, String filter) {
        return matchesGenericFilter(filter,
              Map.of(KEY_VALUE, photo.getValue() != null ? photo.getValue() : "",
                  KEY_TYPE, photo.getType() != null ? photo.getType() : "",
                  KEY_PRIMARY, String.valueOf(photo.isPrimaryFlag())));
    }

    private static boolean matchesCertFilter(ScimUserX509Certificate cert, String filter) {
        return matchesGenericFilter(filter,
              Map.of(KEY_VALUE, cert.getValue() != null ? cert.getValue() : "",
                  KEY_TYPE, cert.getType() != null ? cert.getType() : "",
                  KEY_PRIMARY, String.valueOf(cert.isPrimaryFlag())));
    }

    /**
     * Simple filter matching: supports "attr eq \"value\"" syntax.
     */
    private static boolean matchesGenericFilter(String filter, Map<String, String> attributes) {
        FilterClause clause = parseEqFilter(filter);
        if (clause == null) {
            return false;
        }
        String actual = attributes.get(clause.attribute());
        return actual != null && clause.value().equalsIgnoreCase(actual);
    }

    // ── ATTRIBUTE SETTERS ───────────────────────────────────

    private static void setSingleAttribute(ScimUser user, String attr, Object value) {
        switch (attr) {
            case "userName" -> user.setUserName(toString(value));
            case "externalId" -> user.setExternalId(toString(value));
            case KEY_DISPLAY_NAME -> user.setDisplayName(toString(value));
            case "nickName" -> user.setNickName(toString(value));
            case "profileUrl" -> {
                String ref = toString(value);
                user.setProfileUrl(ref);
            }
            case "title" -> user.setTitle(toString(value));
            case "userType" -> user.setUserType(toString(value));
            case "preferredLanguage" -> user.setPreferredLanguage(toString(value));
            case "locale" -> user.setLocale(toString(value));
            case "timezone" -> user.setTimezone(toString(value));
            case "active" -> user.setActive(toBoolean(value));
            case "password" -> user.setPassword(toString(value));
            default -> throw new ScimException(400, "noTarget", "Unknown attribute: " + attr);
        }
    }

    private static void setSubAttribute(ScimUser user, String path, Object value) {
        String[] parts = path.split("\\.", 2);
        String parent = parts[0];
        String sub = parts[1];

        if ("name".equals(parent)) {
            switch (sub) {
                case KEY_FORMATTED -> user.setNameFormatted(toString(value));
                case "familyName" -> user.setNameFamilyName(toString(value));
                case "givenName" -> user.setNameGivenName(toString(value));
                case "middleName" -> user.setNameMiddleName(toString(value));
                case "honorificPrefix" -> user.setNameHonorificPrefix(toString(value));
                case "honorificSuffix" -> user.setNameHonorificSuffix(toString(value));
                default -> throw new ScimException(400, "noTarget", "Unknown name sub-attribute: " + sub);
            }
        } else {
            throw new ScimException(400, "noTarget", "Unknown complex attribute: " + parent);
        }
    }

    private static void setEnterpriseAttribute(ScimUser user, String attr, Object value) {
        switch (attr) {
            case "employeeNumber" -> user.setEnterpriseEmployeeNumber(toString(value));
            case "costCenter" -> user.setEnterpriseCostCenter(toString(value));
            case "organization" -> user.setEnterpriseOrganization(toString(value));
            case "division" -> user.setEnterpriseDivision(toString(value));
            case "department" -> user.setEnterpriseDepartment(toString(value));
            case "manager" -> setEnterpriseManager(user, value);
            default -> throw new ScimException(400, "noTarget", "Unknown enterprise attribute: " + attr);
        }
    }

    private static void setEnterpriseManager(ScimUser user, Object value) {
        if (value == null) {
            user.setEnterpriseManagerValue(null);
            user.setEnterpriseManagerRef(null);
            user.setEnterpriseManagerDisplay(null);
            return;
        }

        if (value instanceof String strValue) {
            String managerValue = strValue.trim();
            if (managerValue.isEmpty()) {
                user.setEnterpriseManagerValue(null);
                user.setEnterpriseManagerRef(null);
                user.setEnterpriseManagerDisplay(null);
            } else {
                user.setEnterpriseManagerValue(managerValue);
            }
            return;
        }

        if (value instanceof Map<?, ?> rawMap) {
            Map<String, Object> mgr = new LinkedHashMap<>();
            rawMap.forEach((key, mapValue) -> mgr.put(String.valueOf(key), mapValue));
            user.setEnterpriseManagerValue(toString(mgr.get(KEY_VALUE)));
            String ref = toString(mgr.get("$ref"));
            if (ref != null) {
                validateReference(ref, "enterprise.manager.$ref");
            }
            user.setEnterpriseManagerRef(ref);
            user.setEnterpriseManagerDisplay(toString(mgr.get(KEY_DISPLAY_NAME)));
            return;
        }

        throw new ScimException(400, "invalidValue", "Enterprise manager must be a string or object");
    }

    private static void applyValueMap(ScimUser user, Map<String, Object> valueMap) {
        Map<String, Object> normalized = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : valueMap.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();

            if (key.startsWith(ENTERPRISE_PREFIX + ":")) {
                String entAttr = key.substring(ENTERPRISE_PREFIX.length() + 1);
                setEnterpriseAttribute(user, entAttr, val);
            } else if (key.contains(".")) {
                setSubAttribute(user, key, val);
            } else {
                normalized.put(key, val);
            }
        }

        if (!normalized.isEmpty()) {
            ScimUserMapper.applyFromScimInput(user, normalized);
        }
    }

    @SuppressWarnings("unchecked")
    private static void addToMultiValued(ScimUser user, String attr, Object value) {
        List<Map<String, Object>> items;
        if (value instanceof List) {
            items = (List<Map<String, Object>>) value;
        } else if (value instanceof Map) {
            items = List.of((Map<String, Object>) value);
        } else {
            throw new ScimException(400, "invalidSyntax", "Add to multi-valued requires array or object value");
        }

        switch (attr) {
            case ATTR_EMAILS -> addItems(items, user.getEmails(), ScimUserMapper::buildEmail);
            case ATTR_PHONE_NUMBERS -> addItems(items, user.getPhoneNumbers(), ScimUserMapper::buildPhone);
            case ATTR_ADDRESSES -> addItems(items, user.getAddresses(), ScimUserMapper::buildAddress);
            case ATTR_IMS -> addItems(items, user.getIms(), ScimUserMapper::buildIm);
            case ATTR_PHOTOS -> addItems(items, user.getPhotos(), ScimUserMapper::buildPhoto);
            case ATTR_ROLES -> addItems(items, user.getRoles(), ScimUserMapper::buildRole);
            case ATTR_ENTITLEMENTS -> addItems(items, user.getEntitlements(), ScimUserMapper::buildEntitlement);
            case ATTR_X509 -> addItems(items, user.getX509Certificates(), ScimUserMapper::buildCertificate);
            default -> throw new ScimException(400, "noTarget", "Cannot add to attribute: " + attr);
        }
    }

    private static void replaceMultiValued(ScimUser user, String attr, Object value) {
        clearAttribute(user, attr);
        addToMultiValued(user, attr, value);
    }

    private static void clearAttribute(ScimUser user, String attr) {
        switch (attr) {
            case "externalId" -> user.setExternalId(null);
            case KEY_DISPLAY_NAME -> user.setDisplayName(null);
            case "nickName" -> user.setNickName(null);
            case "profileUrl" -> user.setProfileUrl(null);
            case "title" -> user.setTitle(null);
            case "userType" -> user.setUserType(null);
            case "preferredLanguage" -> user.setPreferredLanguage(null);
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
            case ATTR_EMAILS -> user.getEmails().clear();
            case ATTR_PHONE_NUMBERS -> user.getPhoneNumbers().clear();
            case ATTR_ADDRESSES -> user.getAddresses().clear();
            case ATTR_IMS -> user.getIms().clear();
            case ATTR_PHOTOS -> user.getPhotos().clear();
            case ATTR_ENTITLEMENTS -> user.getEntitlements().clear();
            case ATTR_ROLES -> user.getRoles().clear();
            case ATTR_X509 -> user.getX509Certificates().clear();
            default -> throw new ScimException(400, "noTarget", "Cannot remove attribute: " + attr);
        }
    }

    private static void setEmailSubAttribute(ScimUserEmail email, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> email.setValue(toString(value));
            case KEY_TYPE -> email.setType(normalizeCanonical(toString(value), EMAIL_TYPES, "emails.type"));
            case KEY_DISPLAY -> email.setDisplay(toString(value));
            case KEY_PRIMARY -> email.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown email sub-attribute: " + subAttr);
        }
    }

    private static void setPhoneSubAttribute(ScimUserPhoneNumber phone, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> phone.setValue(toString(value));
            case KEY_TYPE -> phone.setType(normalizeCanonical(toString(value), PHONE_TYPES, "phoneNumbers.type"));
            case KEY_DISPLAY -> phone.setDisplay(toString(value));
            case KEY_PRIMARY -> phone.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown phone sub-attribute: " + subAttr);
        }
    }

    private static void setAddressSubAttribute(ScimUserAddress address, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_FORMATTED -> address.setFormatted(toString(value));
            case "streetAddress" -> address.setStreetAddress(toString(value));
            case "locality" -> address.setLocality(toString(value));
            case "region" -> address.setRegion(toString(value));
            case "postalCode" -> address.setPostalCode(toString(value));
            case "country" -> address.setCountry(toString(value));
            case KEY_TYPE -> address.setType(normalizeCanonical(toString(value), ADDRESS_TYPES, "addresses.type"));
            case KEY_PRIMARY -> address.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown address sub-attribute: " + subAttr);
        }
    }

    private static void setImSubAttribute(ScimUserIm im, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> im.setValue(toString(value));
            case KEY_TYPE -> im.setType(normalizeCanonical(toString(value), IM_TYPES, "ims.type"));
            case KEY_DISPLAY -> im.setDisplay(toString(value));
            case KEY_PRIMARY -> im.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown ims sub-attribute: " + subAttr);
        }
    }

    private static void setPhotoSubAttribute(ScimUserPhoto photo, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> {
                String ref = toString(value);
                photo.setValue(ref);
            }
            case KEY_TYPE -> photo.setType(normalizeCanonical(toString(value), PHOTO_TYPES, "photos.type"));
            case KEY_DISPLAY -> photo.setDisplay(toString(value));
            case KEY_PRIMARY -> photo.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown photos sub-attribute: " + subAttr);
        }
    }

    private static void setRoleSubAttribute(ScimUserRole role, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> role.setValue(toString(value));
            case KEY_TYPE -> role.setType(toString(value));
            case KEY_DISPLAY -> role.setDisplay(toString(value));
            case KEY_PRIMARY -> role.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown role sub-attribute: " + subAttr);
        }
    }

    private static void setEntitlementSubAttribute(ScimUserEntitlement ent, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> ent.setValue(toString(value));
            case KEY_TYPE -> ent.setType(toString(value));
            case KEY_DISPLAY -> ent.setDisplay(toString(value));
            case KEY_PRIMARY -> ent.setPrimaryFlag(toBoolean(value));
            default -> throw new ScimException(400, "noTarget", "Unknown entitlements sub-attribute: " + subAttr);
        }
    }

    private static void setCertSubAttribute(ScimUserX509Certificate cert, String subAttr, Object value) {
        if (subAttr == null) return;
        switch (subAttr) {
            case KEY_VALUE -> {
                String binary = toString(value);
                validateBinary(binary, "x509Certificates.value");
                cert.setValue(binary);
            }
            case KEY_TYPE -> cert.setType(toString(value));
            case KEY_DISPLAY -> cert.setDisplay(toString(value));
            case KEY_PRIMARY -> cert.setPrimaryFlag(toBoolean(value));
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
                                     java.util.function.Function<Map<String, Object>, T> mapper) {
        for (Map<String, Object> item : items) {
            target.add(mapper.apply(item));
        }
    }

    private static FilterClause parseEqFilter(String filter) {
        if (filter == null) {
            return null;
        }
        String trimmed = filter.trim();
        int eqIndex = trimmed.toLowerCase(Locale.ROOT).indexOf(" eq ");
        if (eqIndex <= 0) {
            return null;
        }
        String attribute = trimmed.substring(0, eqIndex).trim();
        String rawValue = trimmed.substring(eqIndex + 4).trim();
        if (attribute.isEmpty() || rawValue.isEmpty()) {
            return null;
        }
        if (rawValue.startsWith("\"") && rawValue.endsWith("\"") && rawValue.length() >= 2) {
            return new FilterClause(attribute, rawValue.substring(1, rawValue.length() - 1));
        }
        if ("true".equalsIgnoreCase(rawValue) || "false".equalsIgnoreCase(rawValue)) {
            return new FilterClause(attribute, rawValue);
        }
        return null;
    }

    private record FilterClause(String attribute, String value) {
    }

    // ── MULTI-VALUED CHECK ──────────────────────────────────

    private static boolean isMultiValuedAttribute(String attr) {
        return Set.of(ATTR_EMAILS, ATTR_PHONE_NUMBERS, ATTR_ADDRESSES, ATTR_IMS, ATTR_PHOTOS,
                ATTR_ENTITLEMENTS, ATTR_ROLES, ATTR_X509).contains(attr);
    }

    // ── TYPE HELPERS ────────────────────────────────────────

    private static String normalizeCanonical(String value, Set<String> allowed, String fieldName) {
        if (value == null) return null;
        String normalized = value.toLowerCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            throw new ScimException(400, "invalidValue", "Invalid " + fieldName + ": " + value);
        }
        return normalized;
    }

    private static void validateReference(String value, String fieldName) {
        if (value == null || value.isBlank()) return;
        try {
            java.net.URI uri = new java.net.URI(value);
            if (!uri.isAbsolute()) {
                throw new ScimException(400, "invalidValue", fieldName + " must be an absolute URI");
            }
        } catch (java.net.URISyntaxException e) {
            throw new ScimException(400, "invalidValue", fieldName + " must be a valid URI", e);
        }
    }

    private static void validateBinary(String value, String fieldName) {
        if (value == null || value.isBlank()) return;
        try {
            java.util.Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidValue", fieldName + " must be base64-encoded", e);
        }
    }

    private static String toString(Object value) {
        return value != null ? value.toString() : null;
    }

    private static boolean toBoolean(Object value) {
        if (value instanceof Boolean b) return b;
        if (value instanceof String s) return Boolean.parseBoolean(s);
        return false;
    }
}
