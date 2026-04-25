package de.palsoftware.scim.server.impl.scim.schema;

import java.util.*;

/**
 * Provides SCIM schema definitions per RFC 7643 §7.
 * Returns the full User, Group, EnterpriseUser, ServiceProviderConfig,
 * ResourceType, and Schema definitions.
 */
public class ScimSchemaDefinitions {

        private ScimSchemaDefinitions() {
                /* This utility class should not be instantiated */
        }

        // Schema attribute type constants
        private static final String TYPE_STRING = "string";
        private static final String TYPE_BOOLEAN = "boolean";
        private static final String TYPE_COMPLEX = "complex";
        private static final String TYPE_REFERENCE = "reference";
        private static final String TYPE_INTEGER = "integer";
        private static final String TYPE_BINARY = "binary";
        private static final String MUT_READ_ONLY = "readOnly";
        private static final String MUT_READ_WRITE = "readWrite";
        private static final String MUT_IMMUTABLE = "immutable";
        private static final String UNIQ_NONE = "none";
        private static final String CORE_SCHEMA_URN = "urn:ietf:params:scim:schemas:core:2.0:Schema";
        private static final String KEY_SCHEMAS = "schemas";
        private static final String KEY_ATTRIBUTES = "attributes";
        private static final String KEY_META = "meta";
        private static final String KEY_RESOURCE_TYPE = "resourceType";
        private static final String KEY_LOCATION = "location";
        private static final String KEY_SUB_ATTRIBUTES = "subAttributes";
        private static final String KEY_REFERENCE_TYPES = "referenceTypes";
        private static final String KEY_CANONICAL_VALUES = "canonicalValues";
        private static final String KEY_RETURNED = "returned";
        private static final String VALUE_DEFAULT = "default";
        private static final String ATTR_NAME = "name";
        private static final String ATTR_TYPE = "type";
        private static final String ATTR_DESCRIPTION = "description";
        private static final String ATTR_REQUIRED = "required";
        private static final String ATTR_VALUE = "value";
        private static final String ATTR_DISPLAY = "display";
        private static final String ATTR_PRIMARY = "primary";
        private static final String ATTR_SUPPORTED = "supported";
        private static final String DESCRIPTION_TYPE_LABEL = "The type label";
        private static final String DESCRIPTION_HUMAN_READABLE_NAME = "Human-readable name";
        private static final String DESCRIPTION_PRIMARY_INDICATOR = "Primary indicator";
        private static final String VALUE_OTHER = "other";
        private static final String UNIQ_SERVER = "server";
        private static final String KEY_SCHEMA = "schema";
        private static final String KEY_ENDPOINT = "endpoint";
        private static final String KEY_SCHEMA_EXTENSIONS = "schemaExtensions";
        private static final String KEY_DOCUMENTATION_URI = "documentationUri";
        private static final String KEY_MUTABILITY = "mutability";
        private static final String KEY_UNIQUENESS = "uniqueness";
        private static final String KEY_CASE_EXACT = "caseExact";
        private static final String KEY_MULTI_VALUED = "multiValued";
        private static final String NAME_GROUP = "Group";
        private static final String NAME_SCHEMA = "Schema";
        private static final String NAME_RESOURCE_TYPE = "ResourceType";
        private static final String RESOURCE_TYPE_URN = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
        private static final String REF_EXTERNAL = "external";
        private static final String PAGINATION_CURSOR = "cursor";
        private static final String PAGINATION_INDEX = "index";
        private static final String RETURNED_ALWAYS = "always";
        private static final String DESCRIPTION_THE_VALUE = "The value";
        private static final String ATTR_DISPLAY_NAME = "displayName";
        private static final String ATTR_ID = "id";
        private static final String ATTR_REF = "$ref";
        private static final String NAME_USER = "User";
        private static final String REF_TYPE_URI = "uri";
        private static final String VALUE_WORK = "work";
        private static final String VALUE_HOME = "home";

        public static Map<String, Object> serviceProviderConfig() {
                Map<String, Object> config = new LinkedHashMap<>();
                config.put(KEY_SCHEMAS, List.of("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"));
                config.put(KEY_DOCUMENTATION_URI, "https://datatracker.ietf.org/doc/html/rfc7644");
                config.put("patch", Map.of(ATTR_SUPPORTED, true));
                config.put("bulk", Map.of(ATTR_SUPPORTED, true, "maxOperations", 1000, "maxPayloadSize", 1048576));
                config.put("filter", Map.of(ATTR_SUPPORTED, true, "maxResults", 200));
                config.put("pagination", Map.of(
                                PAGINATION_CURSOR, true,
                                PAGINATION_INDEX, true,
                                "defaultPaginationMode", PAGINATION_INDEX,
                                "defaultPageSize", 10,
                                "maxPageSize", 200,
                                "cursorTimeout", 3600));
                config.put("changePassword", Map.of(ATTR_SUPPORTED, false));
                config.put("sort", Map.of(ATTR_SUPPORTED, true));
                config.put("etag", Map.of(ATTR_SUPPORTED, true));
                config.put("authenticationSchemes", List.of(Map.of(
                                "type", "oauthbearertoken",
                                ATTR_NAME, "OAuth Bearer Token",
                                ATTR_DESCRIPTION, "Authentication scheme using the OAuth Bearer Token Standard",
                                "specUri", "http://www.rfc-editor.org/info/rfc6750")));
                return config;
        }

        public static List<Map<String, Object>> allSchemas() {
                return List.of(
                                userSchema(),
                                groupSchema(),
                                enterpriseUserSchema(),
                                serviceProviderConfigSchema(),
                                resourceTypeSchema(),
                                schemaSchema());
        }

        public static Map<String, Object> getSchemaById(String id) {
                return allSchemas().stream()
                                .filter(s -> id.equals(s.get(ATTR_ID)))
                                .findFirst()
                                .orElse(null);
        }

        public static List<Map<String, Object>> resourceTypes(String baseUrl) {
                List<Map<String, Object>> types = new ArrayList<>();

                Map<String, Object> userRT = new LinkedHashMap<>();
                userRT.put(KEY_SCHEMAS, List.of(RESOURCE_TYPE_URN));
                userRT.put(ATTR_ID, NAME_USER);
                userRT.put(ATTR_NAME, "User");
                userRT.put(ATTR_DESCRIPTION, "User Account");
                userRT.put(KEY_ENDPOINT, "/Users");
                userRT.put(KEY_SCHEMA, "urn:ietf:params:scim:schemas:core:2.0:User");
                userRT.put(KEY_SCHEMA_EXTENSIONS, List.of(Map.of(
                                KEY_SCHEMA, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                                ATTR_REQUIRED, false)));
                Map<String, Object> userMeta = new LinkedHashMap<>();
                userMeta.put(KEY_RESOURCE_TYPE, NAME_RESOURCE_TYPE);
                userMeta.put(KEY_LOCATION, baseUrl + "/ResourceTypes/User");
                userRT.put(KEY_META, userMeta);
                types.add(userRT);

                Map<String, Object> groupRT = new LinkedHashMap<>();
                groupRT.put(KEY_SCHEMAS, List.of(RESOURCE_TYPE_URN));
                groupRT.put(ATTR_ID, NAME_GROUP);
                groupRT.put(ATTR_NAME, NAME_GROUP);
                groupRT.put(ATTR_DESCRIPTION, NAME_GROUP);
                groupRT.put(KEY_ENDPOINT, "/Groups");
                groupRT.put(KEY_SCHEMA, "urn:ietf:params:scim:schemas:core:2.0:Group");
                groupRT.put(KEY_SCHEMA_EXTENSIONS, List.of());
                Map<String, Object> groupMeta = new LinkedHashMap<>();
                groupMeta.put(KEY_RESOURCE_TYPE, NAME_RESOURCE_TYPE);
                groupMeta.put(KEY_LOCATION, baseUrl + "/ResourceTypes/Group");
                groupRT.put(KEY_META, groupMeta);
                types.add(groupRT);

                return types;
        }

        public static Map<String, Object> getResourceTypeById(String id) {
                return getResourceTypeById(id, "");
        }

        public static Map<String, Object> getResourceTypeById(String id, String baseUrl) {
                return resourceTypes(baseUrl).stream()
                                .filter(rt -> id.equals(rt.get(ATTR_ID)) || id.equals(rt.get("name")))
                                .findFirst()
                                .orElse(null);
        }

        // ── SCHEMA DEFINITIONS ─────────────────────────────────

        public static Map<String, Object> userSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, "urn:ietf:params:scim:schemas:core:2.0:User");
                schema.put(ATTR_NAME, NAME_USER);
                schema.put(ATTR_DESCRIPTION, "User Account");

                List<Map<String, Object>> attrs = new ArrayList<>();

                // id
                Map<String, Object> idAttr = withCaseExact(attr(ATTR_ID, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_SERVER,
                                "A unique identifier for a SCIM resource", false));
                idAttr.put(KEY_RETURNED, RETURNED_ALWAYS);
                attrs.add(idAttr);

                // externalId
                attrs.add(withCaseExact(attr("externalId", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_SERVER,
                                "An identifier for the resource as defined by the provisioning client", false)));

                // userName
                attrs.add(attr("userName", TYPE_STRING, true, MUT_READ_WRITE, UNIQ_SERVER,
                                "Unique identifier for the User", false));

                // name (complex)
                Map<String, Object> nameAttr = attr(ATTR_NAME, TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The components of the user's real name", false);
                nameAttr.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr("formatted", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "The full name",
                                                false),
                                attr("familyName", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "The family name",
                                                false),
                                attr("givenName", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "The given name",
                                                false),
                                attr("middleName", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "The middle name",
                                                false),
                                attr("honorificPrefix", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                "The honorific prefix", false),
                                attr("honorificSuffix", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                "The honorific suffix", false)));
                attrs.add(nameAttr);

                // displayName
                attrs.add(attr(ATTR_DISPLAY_NAME, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The name displayed for the user", false));

                // nickName
                attrs.add(attr("nickName", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The casual way to address the user", false));

                // profileUrl
                Map<String, Object> profileUrlAttr = withCaseExact(
                                attr("profileUrl", TYPE_REFERENCE, false, MUT_READ_WRITE, UNIQ_NONE,
                                                "A URI that is a URL to the user's online profile", false));
                profileUrlAttr.put(KEY_REFERENCE_TYPES, List.of(REF_EXTERNAL));
                attrs.add(profileUrlAttr);

                // title
                attrs.add(attr("title", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The user's title", false));

                // userType
                attrs.add(attr("userType", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The type of user", false));

                // preferredLanguage
                attrs.add(attr("preferredLanguage", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Preferred written or spoken language", false));

                // locale
                attrs.add(attr("locale", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "User's default location", false));

                // timezone
                attrs.add(attr("timezone", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The User's time zone", false));

                // active
                attrs.add(attr("active", TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                "A Boolean value indicating the User's administrative status", false));

                // password
                Map<String, Object> passwordAttr = attr("password", TYPE_STRING, false, "writeOnly", UNIQ_NONE,
                                "The User's cleartext password", false);
                passwordAttr.put(KEY_RETURNED, "never");
                attrs.add(passwordAttr);

                // emails (multi-valued complex)
                Map<String, Object> emailsAttr = attr("emails", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Email addresses for the user", true);
                emailsAttr.put(KEY_SUB_ATTRIBUTES, emailsSubAttributes());
                attrs.add(emailsAttr);

                // phoneNumbers
                Map<String, Object> phonesAttr = attr("phoneNumbers", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Phone numbers for the user", true);
                phonesAttr.put(KEY_SUB_ATTRIBUTES, phoneNumbersSubAttributes());
                attrs.add(phonesAttr);

                // ims
                Map<String, Object> imsAttr = attr("ims", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Instant messaging addresses for the user", true);
                imsAttr.put(KEY_SUB_ATTRIBUTES, imsSubAttributes());
                attrs.add(imsAttr);

                // photos
                Map<String, Object> photosAttr = attr("photos", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "URLs of photos of the User", true);
                photosAttr.put(KEY_SUB_ATTRIBUTES, photosSubAttributes());
                attrs.add(photosAttr);

                // addresses
                Map<String, Object> addressesAttr = attr("addresses", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Physical mailing addresses for this User", true);
                addressesAttr.put(KEY_SUB_ATTRIBUTES, addressesSubAttributes());
                attrs.add(addressesAttr);

                // entitlements
                Map<String, Object> entAttr = attr("entitlements", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "A list of entitlements for the User", true);
                entAttr.put(KEY_SUB_ATTRIBUTES, entitlementsSubAttributes());
                attrs.add(entAttr);

                // roles
                Map<String, Object> rolesAttr = attr("roles", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "A list of roles for the User", true);
                rolesAttr.put(KEY_SUB_ATTRIBUTES, rolesSubAttributes());
                attrs.add(rolesAttr);

                // x509Certificates
                Map<String, Object> certsAttr = attr("x509Certificates", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "A list of certificates issued to the User", true);
                certsAttr.put(KEY_SUB_ATTRIBUTES, x509CertificatesSubAttributes());
                attrs.add(certsAttr);

                // groups (readOnly, computed)
                Map<String, Object> groupsAttr = attr("groups", TYPE_COMPLEX, false, MUT_READ_ONLY, UNIQ_NONE,
                                "A list of groups to which the user belongs", true);
                groupsAttr.put(KEY_SUB_ATTRIBUTES, groupsSubAttributes());
                attrs.add(groupsAttr);

                schema.put(KEY_ATTRIBUTES, attrs);

                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                meta.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User");
                schema.put(KEY_META, meta);

                return schema;
        }

        public static Map<String, Object> groupSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, "urn:ietf:params:scim:schemas:core:2.0:Group");
                schema.put(ATTR_NAME, NAME_GROUP);
                schema.put(ATTR_DESCRIPTION, NAME_GROUP);

                List<Map<String, Object>> attrs = new ArrayList<>();
                Map<String, Object> idAttr = withCaseExact(attr(ATTR_ID, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_SERVER,
                                "Unique identifier", false));
                idAttr.put(KEY_RETURNED, RETURNED_ALWAYS);
                attrs.add(idAttr);
                attrs.add(withCaseExact(attr("externalId", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_SERVER,
                                "External identifier", false)));
                attrs.add(attr(ATTR_DISPLAY_NAME, TYPE_STRING, true, MUT_READ_WRITE, UNIQ_NONE,
                                "A human-readable name for the Group", false));

                Map<String, Object> membersAttr = attr("members", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "A list of members of the Group", true);
                membersAttr.put(KEY_SUB_ATTRIBUTES, membersSubAttributes());
                attrs.add(membersAttr);

                schema.put(KEY_ATTRIBUTES, attrs);

                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                meta.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group");
                schema.put(KEY_META, meta);

                return schema;
        }

        public static Map<String, Object> enterpriseUserSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
                schema.put(ATTR_NAME, "EnterpriseUser");
                schema.put(ATTR_DESCRIPTION, "Enterprise User Extension");

                List<Map<String, Object>> attrs = new ArrayList<>();
                attrs.add(attr("employeeNumber", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Employee number",
                                false));
                attrs.add(attr("costCenter", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Cost center", false));
                attrs.add(attr("organization", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Organization", false));
                attrs.add(attr("division", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Division", false));
                attrs.add(attr("department", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Department", false));

                Map<String, Object> managerAttr = attr("manager", TYPE_COMPLEX, false, MUT_READ_WRITE, UNIQ_NONE,
                                "The user's manager", false);
                managerAttr.put(KEY_SUB_ATTRIBUTES, List.of(
                                withCaseExact(attr(ATTR_VALUE, TYPE_STRING, true, MUT_READ_WRITE, UNIQ_NONE,
                                                "Manager user id", false)),
                                managerRefSubAttribute(),
                                attr(ATTR_DISPLAY_NAME, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                                "Manager display name", false)));
                attrs.add(managerAttr);

                schema.put(KEY_ATTRIBUTES, attrs);

                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                meta.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
                schema.put(KEY_META, meta);

                return schema;
        }

        private static Map<String, Object> serviceProviderConfigSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
                schema.put(ATTR_NAME, "ServiceProviderConfig");
                schema.put(ATTR_DESCRIPTION, "Schema for representing the service provider's configuration");
                List<Map<String, Object>> attrs = new ArrayList<>();

                Map<String, Object> documentationUri = withCaseExact(
                                attr(KEY_DOCUMENTATION_URI, TYPE_REFERENCE, false, MUT_READ_ONLY,
                                                UNIQ_NONE, "Service provider documentation", false));
                documentationUri.put(KEY_REFERENCE_TYPES, List.of(REF_EXTERNAL));
                attrs.add(documentationUri);

                Map<String, Object> patch = attr("patch", TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "PATCH configuration", false);
                patch.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether PATCH is supported", false)));
                attrs.add(patch);

                Map<String, Object> bulk = attr("bulk", TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Bulk configuration", false);
                bulk.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether bulk is supported", false),
                                attr("maxOperations", TYPE_INTEGER, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Maximum operations", false),
                                attr("maxPayloadSize", TYPE_INTEGER, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Maximum payload size", false)));
                attrs.add(bulk);

                Map<String, Object> filter = attr("filter", TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Filter configuration", false);
                filter.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether filtering is supported", false),
                                attr("maxResults", TYPE_INTEGER, true, MUT_READ_ONLY, UNIQ_NONE, "Maximum results",
                                                false)));
                attrs.add(filter);

                Map<String, Object> pagination = attr("pagination", TYPE_COMPLEX, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Pagination configuration", false);
                pagination.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(PAGINATION_CURSOR, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Cursor pagination supported", false),
                                attr(PAGINATION_INDEX, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Index pagination supported", false),
                                paginationModeAttr(),
                                attr("defaultPageSize", TYPE_INTEGER, false, MUT_READ_ONLY, UNIQ_NONE,
                                                "Default page size", false),
                                attr("maxPageSize", TYPE_INTEGER, false, MUT_READ_ONLY, UNIQ_NONE, "Max page size",
                                                false),
                                attr("cursorTimeout", TYPE_INTEGER, false, MUT_READ_ONLY, UNIQ_NONE, "Cursor timeout",
                                                false)));
                attrs.add(pagination);

                Map<String, Object> changePassword = attr("changePassword", TYPE_COMPLEX, true, MUT_READ_ONLY,
                                UNIQ_NONE,
                                "Change password configuration", false);
                changePassword.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether changePassword is supported", false)));
                attrs.add(changePassword);

                Map<String, Object> sort = attr("sort", TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Sort configuration", false);
                sort.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether sorting is supported", false)));
                attrs.add(sort);

                Map<String, Object> etag = attr("etag", TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "ETag configuration", false);
                etag.put(KEY_SUB_ATTRIBUTES, List.of(
                                attr(ATTR_SUPPORTED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether ETags are supported", false)));
                attrs.add(etag);

                Map<String, Object> authSchemes = attr("authenticationSchemes", TYPE_COMPLEX, true, MUT_READ_ONLY,
                                UNIQ_NONE,
                                "Authentication schemes", true);
                Map<String, Object> schemeType = attr(ATTR_TYPE, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Scheme type", false);
                schemeType.put(KEY_CANONICAL_VALUES,
                                List.of("httpbasic", "httpdigest", "oauth", "oauth2", "oauthbearertoken"));

                Map<String, Object> specUri = withCaseExact(attr("specUri", TYPE_REFERENCE, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Specification URI", false));
                specUri.put(KEY_REFERENCE_TYPES, List.of(REF_EXTERNAL));

                Map<String, Object> docUri = withCaseExact(attr(KEY_DOCUMENTATION_URI, TYPE_REFERENCE, false,
                                MUT_READ_ONLY, UNIQ_NONE, "Documentation URI", false));
                docUri.put(KEY_REFERENCE_TYPES, List.of(REF_EXTERNAL));

                authSchemes.put(KEY_SUB_ATTRIBUTES, List.of(
                                schemeType,
                                attr(ATTR_NAME, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE, "Scheme name", false),
                                attr(ATTR_DESCRIPTION, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Scheme description", false),
                                specUri,
                                docUri));
                attrs.add(authSchemes);

                schema.put(KEY_ATTRIBUTES, attrs);
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                meta.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
                schema.put(KEY_META, meta);
                return schema;
        }

        private static Map<String, Object> resourceTypeSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, RESOURCE_TYPE_URN);
                schema.put(ATTR_NAME, NAME_RESOURCE_TYPE);
                schema.put(ATTR_DESCRIPTION, "Schema for representing resource types");
                List<Map<String, Object>> attrs = new ArrayList<>();

                attrs.add(attr(ATTR_NAME, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_SERVER, "Resource type name", false));
                attrs.add(attr(ATTR_DESCRIPTION, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Resource type description", false));

                Map<String, Object> endpoint = withCaseExact(
                                attr(KEY_ENDPOINT, TYPE_REFERENCE, true, MUT_READ_ONLY, UNIQ_SERVER,
                                                "Resource type endpoint", false));
                endpoint.put(KEY_REFERENCE_TYPES, List.of(REF_TYPE_URI));
                attrs.add(endpoint);

                Map<String, Object> schemaRef = withCaseExact(
                                attr(KEY_SCHEMA, TYPE_REFERENCE, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Resource schema URI", false));
                schemaRef.put(KEY_REFERENCE_TYPES, List.of(REF_TYPE_URI));
                attrs.add(schemaRef);

                Map<String, Object> schemaExtensions = withCaseExact(
                                attr(KEY_SCHEMA_EXTENSIONS, TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Schema extensions", true));
                schemaExtensions.put(KEY_SUB_ATTRIBUTES, List.of(
                                withCaseExact(attr(KEY_SCHEMA, TYPE_REFERENCE, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Extension schema URI", false)),
                                attr(ATTR_REQUIRED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                                "Whether extension is required", false)));
                @SuppressWarnings("unchecked")
                Map<String, Object> schemaExtSchema = (Map<String, Object>) ((List<?>) schemaExtensions
                                .get(KEY_SUB_ATTRIBUTES)).get(0);
                schemaExtSchema.put(KEY_REFERENCE_TYPES, List.of(REF_TYPE_URI));
                attrs.add(schemaExtensions);

                schema.put(KEY_ATTRIBUTES, attrs);
                Map<String, Object> metaInfo = new LinkedHashMap<>();
                metaInfo.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                metaInfo.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:core:2.0:ResourceType");
                schema.put(KEY_META, metaInfo);
                return schema;
        }

        private static Map<String, Object> schemaSchema() {
                Map<String, Object> schema = new LinkedHashMap<>();
                schema.put(KEY_SCHEMAS, List.of(CORE_SCHEMA_URN));
                schema.put(ATTR_ID, CORE_SCHEMA_URN);
                schema.put(ATTR_NAME, NAME_SCHEMA);
                schema.put(ATTR_DESCRIPTION, "Schema for representing schemas");
                List<Map<String, Object>> attrs = new ArrayList<>();

                attrs.add(attr(ATTR_NAME, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE, "Schema name", false));
                attrs.add(attr(ATTR_DESCRIPTION, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE, "Schema description",
                                false));

                Map<String, Object> attributes = attr(KEY_ATTRIBUTES, TYPE_COMPLEX, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Schema attribute definitions", true);

                // Helper to create list of subAttributes for attributes definition (recursive
                // structure)
                List<Map<String, Object>> attributeSubAttributes = new ArrayList<>();
                attributeSubAttributes.add(withCaseExact(
                                attr(ATTR_NAME, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE, "Attribute name", false)));

                Map<String, Object> typeAttr = attr(ATTR_TYPE, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Attribute type", false);
                typeAttr.put(KEY_CANONICAL_VALUES, List.of(TYPE_STRING, TYPE_BOOLEAN, "decimal", TYPE_INTEGER,
                                "dateTime", TYPE_REFERENCE, TYPE_COMPLEX, TYPE_BINARY));
                attributeSubAttributes.add(typeAttr);

                attributeSubAttributes.add(attr(KEY_MULTI_VALUED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Multi-valued flag", false));
                attributeSubAttributes.add(attr(ATTR_DESCRIPTION, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Attribute description", false));
                attributeSubAttributes.add(attr(ATTR_REQUIRED, TYPE_BOOLEAN, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Required flag", false));

                attributeSubAttributes.add(withCaseExact(attr(KEY_CANONICAL_VALUES, TYPE_STRING, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Canonical values", true)));
                attributeSubAttributes.add(attr(KEY_CASE_EXACT, TYPE_BOOLEAN, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Case exact flag", false));

                Map<String, Object> mutabilityAttr = withCaseExact(attr(KEY_MUTABILITY, TYPE_STRING, false,
                                MUT_READ_ONLY, UNIQ_NONE, "Mutability", false));
                mutabilityAttr.put(KEY_CANONICAL_VALUES,
                                List.of(MUT_READ_ONLY, MUT_READ_WRITE, MUT_IMMUTABLE, "writeOnly"));
                attributeSubAttributes.add(mutabilityAttr);

                Map<String, Object> returnedAttr = withCaseExact(attr(KEY_RETURNED, TYPE_STRING, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Returned behavior", false));
                returnedAttr.put(KEY_CANONICAL_VALUES, List.of(RETURNED_ALWAYS, "never", VALUE_DEFAULT, "request"));
                attributeSubAttributes.add(returnedAttr);

                Map<String, Object> uniquenessAttr = withCaseExact(attr(KEY_UNIQUENESS, TYPE_STRING, false,
                                MUT_READ_ONLY, UNIQ_NONE, "Uniqueness", false));
                uniquenessAttr.put(KEY_CANONICAL_VALUES, List.of(UNIQ_NONE, UNIQ_SERVER, "global"));
                attributeSubAttributes.add(uniquenessAttr);

                attributeSubAttributes.add(withCaseExact(attr(KEY_REFERENCE_TYPES, TYPE_STRING, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Reference types", true)));

                // This is recursive: subAttributes contains subAttributes. We leave the inner
                // one generic to stop infinite recursion
                // or we replicate the structure one level deep as SCIM spec might imply.
                // RFC 7643 does not specify depth, but typically schema definitions stop at one
                // level of recursion in the schema schema itself.
                // However, we should define 'subAttributes' with the same structure as
                // 'attributes'
                Map<String, Object> subAttributesAttr = attr(KEY_SUB_ATTRIBUTES, TYPE_COMPLEX, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Sub-attributes", true);
                // We will reuse the same list for subAttributes property.
                // Note: strictly speaking this makes a cycle, but in JSON serialization it
                // might be problematic if we just pass the reference.
                // Here we just don't add subAttributes to itself to avoid StackOverflow in
                // serialization if we were serializing this object graph directly (though we
                // are using Maps).
                // To satisfy the checker, we should provide the list of properties for
                // 'subAttributes'.
                // Since we cannot do infinite recursion, we provide a simplified version or the
                // keys.
                // Let's create a fresh list copy for the inner subAttributes to avoid reference
                // cycles.
                List<Map<String, Object>> innerSubAttributes = new ArrayList<>();
                innerSubAttributes.add(withCaseExact(
                                attr(ATTR_NAME, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE, "Attribute name", false)));
                innerSubAttributes.add(
                                attr(ATTR_TYPE, TYPE_STRING, true, MUT_READ_ONLY, UNIQ_NONE, "Attribute type", false));
                innerSubAttributes.add(attr(KEY_MULTI_VALUED, TYPE_BOOLEAN, true, MUT_READ_ONLY, UNIQ_NONE,
                                "Multi-valued flag", false));
                innerSubAttributes.add(attr(ATTR_DESCRIPTION, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Attribute description", false));
                innerSubAttributes.add(attr(ATTR_REQUIRED, TYPE_BOOLEAN, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Required flag", false));
                innerSubAttributes.add(withCaseExact(attr(KEY_CANONICAL_VALUES, TYPE_STRING, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Canonical values", true)));
                innerSubAttributes.add(attr(KEY_CASE_EXACT, TYPE_BOOLEAN, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Case exact flag", false));
                innerSubAttributes.add(withCaseExact(attr(KEY_MUTABILITY, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Mutability", false)));
                innerSubAttributes.add(withCaseExact(attr(KEY_RETURNED, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Returned behavior", false)));
                innerSubAttributes.add(withCaseExact(attr(KEY_UNIQUENESS, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Uniqueness", false)));
                innerSubAttributes.add(withCaseExact(attr(KEY_REFERENCE_TYPES, TYPE_STRING, false, MUT_READ_ONLY,
                                UNIQ_NONE, "Reference types", true)));

                subAttributesAttr.put(KEY_SUB_ATTRIBUTES, innerSubAttributes);
                attributeSubAttributes.add(subAttributesAttr);

                attributes.put(KEY_SUB_ATTRIBUTES, attributeSubAttributes);
                attrs.add(attributes);

                schema.put(KEY_ATTRIBUTES, attrs);
                Map<String, Object> metaInfo = new LinkedHashMap<>();
                metaInfo.put(KEY_RESOURCE_TYPE, NAME_SCHEMA);
                metaInfo.put(KEY_LOCATION, "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Schema");
                schema.put(KEY_META, metaInfo);
                return schema;
        }

        private static Map<String, Object> paginationModeAttr() {
                Map<String, Object> a = attr("defaultPaginationMode", TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Default pagination mode", false);
                a.put(KEY_CANONICAL_VALUES, List.of(PAGINATION_CURSOR, PAGINATION_INDEX));
                a.remove(KEY_UNIQUENESS);
                return a;
        }

        // ── HELPERS ──────────────────────────────────────────────

        private static Map<String, Object> attr(String name, String type, boolean required,
                        String mutability, String uniqueness,
                        String description, boolean multiValued) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put(ATTR_NAME, name);
                a.put(ATTR_TYPE, type);
                a.put(KEY_MULTI_VALUED, multiValued);
                a.put(ATTR_DESCRIPTION, description);
                a.put(ATTR_REQUIRED, required);
                a.put(KEY_MUTABILITY, mutability);
                a.put(KEY_RETURNED, VALUE_DEFAULT);
                boolean supportsStringAttrs = TYPE_STRING.equals(type) || TYPE_REFERENCE.equals(type);
                if (supportsStringAttrs)
                        a.put(KEY_CASE_EXACT, false);
                if (supportsStringAttrs)
                        a.put(KEY_UNIQUENESS, uniqueness);
                return a;
        }

        private static Map<String, Object> withCaseExact(Map<String, Object> a) {
                a.put(KEY_CASE_EXACT, true);
                return a;
        }

        private static Map<String, Object> managerRefSubAttribute() {
                Map<String, Object> ref = withCaseExact(attr(ATTR_REF, TYPE_REFERENCE, true, MUT_READ_WRITE, UNIQ_NONE,
                                "Manager URI", false));
                ref.put(KEY_REFERENCE_TYPES, List.of(NAME_USER));
                return ref;
        }

        private static List<Map<String, Object>> emailsSubAttributes() {
                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                DESCRIPTION_TYPE_LABEL, false);
                type.put(KEY_CANONICAL_VALUES, List.of(VALUE_WORK, VALUE_HOME, VALUE_OTHER));
                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_THE_VALUE,
                                                false),
                                type,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> phoneNumbersSubAttributes() {
                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                DESCRIPTION_TYPE_LABEL, false);
                type.put(KEY_CANONICAL_VALUES, List.of(VALUE_WORK, VALUE_HOME, "mobile", "fax", "pager", VALUE_OTHER));
                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_THE_VALUE,
                                                false),
                                type,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> imsSubAttributes() {
                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                DESCRIPTION_TYPE_LABEL, false);
                type.put(KEY_CANONICAL_VALUES, List.of("aim", "gtalk", "icq", "xmpp", "skype", "qq", "msn", "yahoo"));
                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_THE_VALUE,
                                                false),
                                type,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> photosSubAttributes() {
                Map<String, Object> value = withCaseExact(
                                attr(ATTR_VALUE, TYPE_REFERENCE, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_THE_VALUE, false));
                value.put(KEY_REFERENCE_TYPES, List.of(REF_EXTERNAL));

                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                DESCRIPTION_TYPE_LABEL, false);
                type.put(KEY_CANONICAL_VALUES, List.of("photo", "thumbnail"));

                return List.of(
                                value,
                                type,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> addressesSubAttributes() {
                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                "Address type (work, home, other)", false);
                type.put(KEY_CANONICAL_VALUES, List.of(VALUE_WORK, VALUE_HOME, VALUE_OTHER));

                return List.of(
                                attr("formatted", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Full mailing address",
                                                false),
                                attr("streetAddress", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Street address",
                                                false),
                                attr("locality", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "City or locality",
                                                false),
                                attr("region", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "State or region", false),
                                attr("postalCode", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Postal code", false),
                                attr("country", TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, "Country", false),
                                type,
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                "Primary address indicator", false));
        }

        private static List<Map<String, Object>> entitlementsSubAttributes() {
                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_THE_VALUE,
                                                false),
                                attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_TYPE_LABEL,
                                                false),
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> rolesSubAttributes() {
                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_THE_VALUE,
                                                false),
                                attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_TYPE_LABEL,
                                                false),
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> x509CertificatesSubAttributes() {
                Map<String, Object> value = attr(ATTR_VALUE, TYPE_BINARY, false, MUT_READ_WRITE, UNIQ_NONE,
                                DESCRIPTION_THE_VALUE, false);
                value.put(KEY_CASE_EXACT, true);

                return List.of(
                                value,
                                attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE, DESCRIPTION_TYPE_LABEL,
                                                false),
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_HUMAN_READABLE_NAME, false),
                                attr(ATTR_PRIMARY, TYPE_BOOLEAN, false, MUT_READ_WRITE, UNIQ_NONE,
                                                DESCRIPTION_PRIMARY_INDICATOR, false));
        }

        private static List<Map<String, Object>> groupsSubAttributes() {
                Map<String, Object> ref = withCaseExact(attr(ATTR_REF, TYPE_REFERENCE, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Group URI", false));
                ref.put(KEY_REFERENCE_TYPES, List.of(NAME_GROUP));

                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE,
                                "Membership type", false);
                type.put(KEY_CANONICAL_VALUES, List.of("direct", "indirect"));

                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE, "Group id", false),
                                ref,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE, "Group displayName",
                                                false),
                                type);
        }

        private static List<Map<String, Object>> membersSubAttributes() {
                Map<String, Object> ref = withCaseExact(attr(ATTR_REF, TYPE_REFERENCE, false, MUT_IMMUTABLE, UNIQ_NONE,
                                "Member URI", false));
                ref.put(KEY_REFERENCE_TYPES, List.of(NAME_USER, NAME_GROUP));

                Map<String, Object> type = attr(ATTR_TYPE, TYPE_STRING, false, MUT_IMMUTABLE, UNIQ_NONE,
                                "Member type (User or Group)", false);
                type.put(KEY_CANONICAL_VALUES, List.of(NAME_USER, NAME_GROUP));

                return List.of(
                                attr(ATTR_VALUE, TYPE_STRING, false, MUT_IMMUTABLE, UNIQ_NONE, "Member identifier",
                                                false),
                                ref,
                                attr(ATTR_DISPLAY, TYPE_STRING, false, MUT_READ_ONLY, UNIQ_NONE, "Member display name",
                                                false),
                                type);
        }
}
