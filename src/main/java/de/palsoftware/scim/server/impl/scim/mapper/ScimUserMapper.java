package de.palsoftware.scim.server.impl.scim.mapper;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
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

/**
 * Converts between JPA entities and SCIM JSON Maps.
 * All SCIM responses are built as Map<String,Object> for maximum flexibility.
 */
public class ScimUserMapper {

    private ScimUserMapper() {
    }

    public static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    public static final String ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String VALUE_OTHER = "other";

    private static final List<String> SCHEMAS_CORE = List.of(USER_SCHEMA);
    private static final List<String> SCHEMAS_ENTERPRISE = List.of(USER_SCHEMA, ENTERPRISE_SCHEMA);

    private static final Set<String> EMAIL_TYPES = Set.of("work", "home", VALUE_OTHER);
    private static final Set<String> PHONE_TYPES = Set.of("work", "home", "mobile", "fax", "pager", VALUE_OTHER);
    private static final Set<String> IM_TYPES = Set.of("aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo");
    private static final Set<String> PHOTO_TYPES = Set.of("photo", "thumbnail");
    private static final Set<String> ADDRESS_TYPES = Set.of("work", "home", VALUE_OTHER);

    // Common SCIM attribute keys
    private static final String KEY_SCHEMAS = "schemas";
    private static final String KEY_EXTERNAL_ID = "externalId";
    private static final String KEY_USER_NAME = "userName";
    private static final String KEY_DISPLAY_NAME = "displayName";
    private static final String KEY_NICK_NAME = "nickName";
    private static final String KEY_PROFILE_URL = "profileUrl";
    private static final String KEY_TITLE = "title";
    private static final String KEY_USER_TYPE = "userType";
    private static final String KEY_PREFERRED_LANGUAGE = "preferredLanguage";
    private static final String KEY_LOCALE = "locale";
    private static final String KEY_TIMEZONE = "timezone";
    private static final String KEY_ACTIVE = "active";
    private static final String KEY_EMAILS = "emails";
    private static final String KEY_PHONE_NUMBERS = "phoneNumbers";
    private static final String KEY_PHOTOS = "photos";
    private static final String KEY_ADDRESSES = "addresses";
    private static final String KEY_ENTITLEMENTS = "entitlements";
    private static final String KEY_ROLES = "roles";
    private static final String KEY_X509_CERTIFICATES = "x509Certificates";
    private static final String KEY_MANAGER = "manager";
    private static final String KEY_VALUE = "value";
    private static final String KEY_TYPE = "type";
    private static final String KEY_PRIMARY = "primary";
    private static final String KEY_DISPLAY = "display";
    private static final String KEY_FORMATTED = "formatted";

    /**
     * Convert ScimUser entity to SCIM JSON response map.
     */
    public static Map<String, Object> toScimResponse(ScimUser user, String baseUrl,
                                                       List<Map<String, Object>> groups) {
        boolean hasEnterprise = hasEnterpriseData(user);
        Map<String, Object> result = new LinkedHashMap<>(hasEnterprise ? 20 : 16);

        addSchemasAndIdentifiers(user, result, hasEnterprise);
        addCoreAttributes(user, result);
        addMultiValuedAttributes(user, result);
        addComputedGroups(result, groups);
        if (hasEnterprise) {
            addEnterpriseExtension(user, result);
        }
        addMeta(user, baseUrl, result);

        return result;
    }

    private static void addSchemasAndIdentifiers(ScimUser user, Map<String, Object> result,
                                                  boolean hasEnterprise) {
        result.put(KEY_SCHEMAS, hasEnterprise ? SCHEMAS_ENTERPRISE : SCHEMAS_CORE);
        result.put("id", user.getId().toString());
        if (user.getExternalId() != null) {
            result.put(KEY_EXTERNAL_ID, user.getExternalId());
        }
        result.put(KEY_USER_NAME, user.getUserName());
    }

    private static void addCoreAttributes(ScimUser user, Map<String, Object> result) {
        Map<String, Object> name = buildNameMap(user);
        if (!name.isEmpty()) {
            result.put("name", name);
        }

        putIfNotNull(result, KEY_DISPLAY_NAME, user.getDisplayName());
        putIfNotNull(result, KEY_NICK_NAME, user.getNickName());
        putIfNotNull(result, KEY_PROFILE_URL, user.getProfileUrl());
        putIfNotNull(result, KEY_TITLE, user.getTitle());
        putIfNotNull(result, KEY_USER_TYPE, user.getUserType());
        putIfNotNull(result, KEY_PREFERRED_LANGUAGE, user.getPreferredLanguage());
        putIfNotNull(result, KEY_LOCALE, user.getLocale());
        putIfNotNull(result, KEY_TIMEZONE, user.getTimezone());
        result.put(KEY_ACTIVE, user.isActive());
    }

    private static void addMultiValuedAttributes(ScimUser user, Map<String, Object> result) {
        putCollection(result, KEY_EMAILS, user.getEmails(), ScimUserMapper::emailToMap);
        putCollection(result, KEY_PHONE_NUMBERS, user.getPhoneNumbers(), ScimUserMapper::phoneToMap);
        putCollection(result, "ims", user.getIms(), ScimUserMapper::imToMap);
        putCollection(result, KEY_PHOTOS, user.getPhotos(), ScimUserMapper::photoToMap);
        putCollection(result, KEY_ADDRESSES, user.getAddresses(), ScimUserMapper::addressToMap);
        putCollection(result, KEY_ENTITLEMENTS, user.getEntitlements(), ScimUserMapper::entitlementToMap);
        putCollection(result, KEY_ROLES, user.getRoles(), ScimUserMapper::roleToMap);
        putCollection(result, KEY_X509_CERTIFICATES, user.getX509Certificates(), ScimUserMapper::certToMap);
    }

    private static void addComputedGroups(Map<String, Object> result, List<Map<String, Object>> groups) {
        if (groups != null && !groups.isEmpty()) {
            result.put("groups", groups);
        }
    }

    private static void addEnterpriseExtension(ScimUser user, Map<String, Object> result) {
        Map<String, Object> enterprise = new LinkedHashMap<>(8);
        putIfNotNull(enterprise, "employeeNumber", user.getEnterpriseEmployeeNumber());
        putIfNotNull(enterprise, "costCenter", user.getEnterpriseCostCenter());
        putIfNotNull(enterprise, "organization", user.getEnterpriseOrganization());
        putIfNotNull(enterprise, "division", user.getEnterpriseDivision());
        putIfNotNull(enterprise, "department", user.getEnterpriseDepartment());

        Map<String, Object> manager = buildManagerMap(user);
        if (!manager.isEmpty()) {
            enterprise.put(KEY_MANAGER, manager);
        }

        result.put(ENTERPRISE_SCHEMA, enterprise);
    }

    private static void addMeta(ScimUser user, String baseUrl, Map<String, Object> result) {
        Map<String, Object> meta = new LinkedHashMap<>(6);
        meta.put("resourceType", "User");
        meta.put("created", user.getCreatedAt().toString());
        meta.put("lastModified", user.getLastModified().toString());
        meta.put("location", baseUrl + "/Users/" + user.getId());
        meta.put("version", "W/\"" + user.getVersion() + "\"");
        result.put("meta", meta);
    }

    /**
     * Apply SCIM JSON input to a ScimUser entity (for CREATE and PUT).
     */
    public static void applyFromScimInput(ScimUser user, Map<String, Object> input) {
        applySimpleAttributes(user, input);
        applyNameAttribute(user, input.get("name"));
        replaceCollection(user.getEmails(), input, KEY_EMAILS, item -> buildEmail(item));
        replaceCollection(user.getPhoneNumbers(), input, KEY_PHONE_NUMBERS, item -> buildPhone(item));
        replaceCollection(user.getAddresses(), input, KEY_ADDRESSES, item -> buildAddress(item));
        replaceCollection(user.getIms(), input, "ims", item -> buildIm(item));
        replaceCollection(user.getPhotos(), input, KEY_PHOTOS, item -> buildPhoto(item));
        replaceCollection(user.getEntitlements(), input, KEY_ENTITLEMENTS, item -> buildEntitlement(item));
        replaceCollection(user.getRoles(), input, KEY_ROLES, item -> buildRole(item));
        replaceCollection(user.getX509Certificates(), input, KEY_X509_CERTIFICATES, item -> buildCertificate(item));
        applyEnterpriseExtension(user, input);
    }

    /**
     * Clear all mutable attributes for PUT (full replacement).
     */
    public static void clearMutableAttributes(ScimUser user) {
        user.setExternalId(null);
        user.setNameFormatted(null);
        user.setNameFamilyName(null);
        user.setNameGivenName(null);
        user.setNameMiddleName(null);
        user.setNameHonorificPrefix(null);
        user.setNameHonorificSuffix(null);
        user.setDisplayName(null);
        user.setNickName(null);
        user.setProfileUrl(null);
        user.setTitle(null);
        user.setUserType(null);
        user.setPreferredLanguage(null);
        user.setLocale(null);
        user.setTimezone(null);
        user.setActive(true);
        user.setPassword(null);
        user.getEmails().clear();
        user.getPhoneNumbers().clear();
        user.getAddresses().clear();
        user.getIms().clear();
        user.getPhotos().clear();
        user.getEntitlements().clear();
        user.getRoles().clear();
        user.getX509Certificates().clear();
        user.setEnterpriseEmployeeNumber(null);
        user.setEnterpriseCostCenter(null);
        user.setEnterpriseOrganization(null);
        user.setEnterpriseDivision(null);
        user.setEnterpriseDepartment(null);
        user.setEnterpriseManagerValue(null);
        user.setEnterpriseManagerRef(null);
        user.setEnterpriseManagerDisplay(null);
    }

    // ── Helper methods ─────────────────────────────────────────

    private static boolean hasEnterpriseData(ScimUser user) {
        return user.getEnterpriseEmployeeNumber() != null ||
               user.getEnterpriseCostCenter() != null ||
               user.getEnterpriseOrganization() != null ||
               user.getEnterpriseDivision() != null ||
               user.getEnterpriseDepartment() != null ||
               user.getEnterpriseManagerValue() != null;
    }

    private static Map<String, Object> buildNameMap(ScimUser user) {
        Map<String, Object> name = new LinkedHashMap<>(8);
        if (user.getNameFormatted() != null) name.put(KEY_FORMATTED, user.getNameFormatted());
        if (user.getNameFamilyName() != null) name.put("familyName", user.getNameFamilyName());
        if (user.getNameGivenName() != null) name.put("givenName", user.getNameGivenName());
        if (user.getNameMiddleName() != null) name.put("middleName", user.getNameMiddleName());
        if (user.getNameHonorificPrefix() != null) name.put("honorificPrefix", user.getNameHonorificPrefix());
        if (user.getNameHonorificSuffix() != null) name.put("honorificSuffix", user.getNameHonorificSuffix());
        return name;
    }

    private static Map<String, Object> buildManagerMap(ScimUser user) {
        Map<String, Object> manager = new LinkedHashMap<>(4);
        putIfNotNull(manager, KEY_VALUE, user.getEnterpriseManagerValue());
        putIfNotNull(manager, "$ref", user.getEnterpriseManagerRef());
        putIfNotNull(manager, KEY_DISPLAY_NAME, user.getEnterpriseManagerDisplay());
        return manager;
    }

    private static void putIfNotNull(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private static <T> void putCollection(Map<String, Object> target, String key, List<T> values,
                                          java.util.function.Function<T, Map<String, Object>> mapper) {
        if (values != null && !values.isEmpty()) {
            List<Map<String, Object>> list = new ArrayList<>(values.size());
            for (T v : values) {
                list.add(mapper.apply(v));
            }
            target.put(key, list);
        }
    }

    private static void applySimpleAttributes(ScimUser user, Map<String, Object> input) {
        if (input.containsKey(KEY_USER_NAME)) user.setUserName((String) input.get(KEY_USER_NAME));
        if (input.containsKey(KEY_EXTERNAL_ID)) user.setExternalId((String) input.get(KEY_EXTERNAL_ID));
        if (input.containsKey(KEY_DISPLAY_NAME)) user.setDisplayName((String) input.get(KEY_DISPLAY_NAME));
        if (input.containsKey(KEY_NICK_NAME)) user.setNickName((String) input.get(KEY_NICK_NAME));
        if (input.containsKey(KEY_PROFILE_URL)) user.setProfileUrl((String) input.get(KEY_PROFILE_URL));
        if (input.containsKey(KEY_TITLE)) user.setTitle((String) input.get(KEY_TITLE));
        if (input.containsKey(KEY_USER_TYPE)) user.setUserType((String) input.get(KEY_USER_TYPE));
        if (input.containsKey(KEY_PREFERRED_LANGUAGE)) user.setPreferredLanguage((String) input.get(KEY_PREFERRED_LANGUAGE));
        if (input.containsKey(KEY_LOCALE)) user.setLocale((String) input.get(KEY_LOCALE));
        if (input.containsKey(KEY_TIMEZONE)) user.setTimezone((String) input.get(KEY_TIMEZONE));
        if (input.containsKey(KEY_ACTIVE)) user.setActive(toBoolean(input.get(KEY_ACTIVE)));
        if (input.containsKey("password")) user.setPassword((String) input.get("password"));
    }

    @SuppressWarnings("unchecked")
    private static void applyNameAttribute(ScimUser user, Object nameObj) {
        if (!(nameObj instanceof Map<?, ?> rawNameMap)) {
            return;
        }
        Map<String, Object> nameMap = (Map<String, Object>) rawNameMap;
        user.setNameFormatted((String) nameMap.get(KEY_FORMATTED));
        user.setNameFamilyName((String) nameMap.get("familyName"));
        user.setNameGivenName((String) nameMap.get("givenName"));
        user.setNameMiddleName((String) nameMap.get("middleName"));
        user.setNameHonorificPrefix((String) nameMap.get("honorificPrefix"));
        user.setNameHonorificSuffix((String) nameMap.get("honorificSuffix"));
    }

    @SuppressWarnings("unchecked")
    private static <T> void replaceCollection(List<T> target, Map<String, Object> input, String key,
                                              java.util.function.Function<Map<String, Object>, T> mapper) {
        if (!input.containsKey(key)) {
            return;
        }
        target.clear();
        List<Map<String, Object>> items = (List<Map<String, Object>>) input.get(key);
        if (items == null) {
            return;
        }
        for (Map<String, Object> item : items) {
            target.add(mapper.apply(item));
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyEnterpriseExtension(ScimUser user, Map<String, Object> input) {
        Map<String, Object> enterprise = (Map<String, Object>) input.get(ENTERPRISE_SCHEMA);
        if (enterprise == null) {
            return;
        }
        user.setEnterpriseEmployeeNumber((String) enterprise.get("employeeNumber"));
        user.setEnterpriseCostCenter((String) enterprise.get("costCenter"));
        user.setEnterpriseOrganization((String) enterprise.get("organization"));
        user.setEnterpriseDivision((String) enterprise.get("division"));
        user.setEnterpriseDepartment((String) enterprise.get("department"));
        applyEnterpriseManager(user, enterprise.get(KEY_MANAGER));
    }

    @SuppressWarnings("unchecked")
    private static void applyEnterpriseManager(ScimUser user, Object managerObj) {
        if (managerObj instanceof Map<?, ?> rawManager) {
            Map<String, Object> manager = (Map<String, Object>) rawManager;
            user.setEnterpriseManagerValue((String) manager.get(KEY_VALUE));
            user.setEnterpriseManagerRef((String) manager.get("$ref"));
            user.setEnterpriseManagerDisplay((String) manager.get(KEY_DISPLAY_NAME));
            return;
        }
        if (managerObj instanceof String managerValue) {
            user.setEnterpriseManagerValue(managerValue);
        }
    }

    public static ScimUserEmail buildEmail(Map<String, Object> item) {
        ScimUserEmail email = new ScimUserEmail();
        email.setValue((String) item.get(KEY_VALUE));
        email.setType(normalizeCanonical((String) item.get(KEY_TYPE), EMAIL_TYPES, "emails.type"));
        email.setDisplay((String) item.get(KEY_DISPLAY));
        email.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return email;
    }

    public static ScimUserPhoneNumber buildPhone(Map<String, Object> item) {
        ScimUserPhoneNumber phone = new ScimUserPhoneNumber();
        phone.setValue((String) item.get(KEY_VALUE));
        phone.setType(normalizeCanonical((String) item.get(KEY_TYPE), PHONE_TYPES, "phoneNumbers.type"));
        phone.setDisplay((String) item.get(KEY_DISPLAY));
        phone.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return phone;
    }

    public static ScimUserAddress buildAddress(Map<String, Object> item) {
        ScimUserAddress address = new ScimUserAddress();
        address.setFormatted((String) item.get(KEY_FORMATTED));
        address.setStreetAddress((String) item.get("streetAddress"));
        address.setLocality((String) item.get("locality"));
        address.setRegion((String) item.get("region"));
        address.setPostalCode((String) item.get("postalCode"));
        address.setCountry((String) item.get("country"));
        address.setType(normalizeCanonical((String) item.get(KEY_TYPE), ADDRESS_TYPES, "addresses.type"));
        address.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return address;
    }

    public static ScimUserIm buildIm(Map<String, Object> item) {
        ScimUserIm im = new ScimUserIm();
        im.setValue((String) item.get(KEY_VALUE));
        im.setType(normalizeCanonical((String) item.get(KEY_TYPE), IM_TYPES, "ims.type"));
        im.setDisplay((String) item.get(KEY_DISPLAY));
        im.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return im;
    }

    public static ScimUserPhoto buildPhoto(Map<String, Object> item) {
        ScimUserPhoto photo = new ScimUserPhoto();
        photo.setValue((String) item.get(KEY_VALUE));
        photo.setType(normalizeCanonical((String) item.get(KEY_TYPE), PHOTO_TYPES, "photos.type"));
        photo.setDisplay((String) item.get(KEY_DISPLAY));
        photo.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return photo;
    }

    public static ScimUserEntitlement buildEntitlement(Map<String, Object> item) {
        ScimUserEntitlement entitlement = new ScimUserEntitlement();
        entitlement.setValue((String) item.get(KEY_VALUE));
        entitlement.setType((String) item.get(KEY_TYPE));
        entitlement.setDisplay((String) item.get(KEY_DISPLAY));
        entitlement.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return entitlement;
    }

    public static ScimUserRole buildRole(Map<String, Object> item) {
        ScimUserRole role = new ScimUserRole();
        role.setValue((String) item.get(KEY_VALUE));
        role.setType((String) item.get(KEY_TYPE));
        role.setDisplay((String) item.get(KEY_DISPLAY));
        role.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        return role;
    }

    public static ScimUserX509Certificate buildCertificate(Map<String, Object> item) {
        ScimUserX509Certificate certificate = new ScimUserX509Certificate();
        certificate.setValue((String) item.get(KEY_VALUE));
        certificate.setType((String) item.get(KEY_TYPE));
        certificate.setDisplay((String) item.get(KEY_DISPLAY));
        certificate.setPrimaryFlag(toBoolean(item.get(KEY_PRIMARY)));
        validateBinary(certificate.getValue(), "x509Certificates.value");
        return certificate;
    }

    private static Map<String, Object> emailToMap(ScimUserEmail e) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, e.getValue());
        if (e.getType() != null) m.put(KEY_TYPE, e.getType());
        if (e.getDisplay() != null) m.put(KEY_DISPLAY, e.getDisplay());
        m.put(KEY_PRIMARY, e.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> phoneToMap(ScimUserPhoneNumber p) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, p.getValue());
        if (p.getType() != null) m.put(KEY_TYPE, p.getType());
        if (p.getDisplay() != null) m.put(KEY_DISPLAY, p.getDisplay());
        m.put(KEY_PRIMARY, p.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> imToMap(ScimUserIm i) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, i.getValue());
        if (i.getType() != null) m.put(KEY_TYPE, i.getType());
        if (i.getDisplay() != null) m.put(KEY_DISPLAY, i.getDisplay());
        m.put(KEY_PRIMARY, i.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> photoToMap(ScimUserPhoto p) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, p.getValue());
        if (p.getType() != null) m.put(KEY_TYPE, p.getType());
        if (p.getDisplay() != null) m.put(KEY_DISPLAY, p.getDisplay());
        m.put(KEY_PRIMARY, p.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> addressToMap(ScimUserAddress a) {
        Map<String, Object> m = new LinkedHashMap<>(9);
        if (a.getFormatted() != null) m.put(KEY_FORMATTED, a.getFormatted());
        if (a.getStreetAddress() != null) m.put("streetAddress", a.getStreetAddress());
        if (a.getLocality() != null) m.put("locality", a.getLocality());
        if (a.getRegion() != null) m.put("region", a.getRegion());
        if (a.getPostalCode() != null) m.put("postalCode", a.getPostalCode());
        if (a.getCountry() != null) m.put("country", a.getCountry());
        if (a.getType() != null) m.put(KEY_TYPE, a.getType());
        m.put(KEY_PRIMARY, a.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> entitlementToMap(ScimUserEntitlement e) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, e.getValue());
        if (e.getType() != null) m.put(KEY_TYPE, e.getType());
        if (e.getDisplay() != null) m.put(KEY_DISPLAY, e.getDisplay());
        m.put(KEY_PRIMARY, e.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> roleToMap(ScimUserRole r) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, r.getValue());
        if (r.getType() != null) m.put(KEY_TYPE, r.getType());
        if (r.getDisplay() != null) m.put(KEY_DISPLAY, r.getDisplay());
        m.put(KEY_PRIMARY, r.isPrimaryFlag());
        return m;
    }

    private static Map<String, Object> certToMap(ScimUserX509Certificate c) {
        Map<String, Object> m = new LinkedHashMap<>(5);
        m.put(KEY_VALUE, c.getValue());
        if (c.getType() != null) m.put(KEY_TYPE, c.getType());
        if (c.getDisplay() != null) m.put(KEY_DISPLAY, c.getDisplay());
        m.put(KEY_PRIMARY, c.isPrimaryFlag());
        return m;
    }

    private static String normalizeCanonical(String value, Set<String> allowed, String fieldName) {
        if (value == null) return null;
        String normalized = value.toLowerCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            throw new ScimException(400, "invalidValue", "Invalid " + fieldName + ": " + value);
        }
        return normalized;
    }

    private static void validateBinary(String value, String fieldName) {
        if (value == null || value.isBlank()) return;
        try {
            java.util.Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidValue", fieldName + " must be base64-encoded", e);
        }
    }

    private static boolean toBoolean(Object value) {
        if (value instanceof Boolean b) return b;
        if (value instanceof String s) return Boolean.parseBoolean(s);
        return false;
    }
}
