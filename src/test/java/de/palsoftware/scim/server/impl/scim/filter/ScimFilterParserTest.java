package de.palsoftware.scim.server.impl.scim.filter;

import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import jakarta.persistence.criteria.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.data.jpa.domain.Specification;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SuppressWarnings({"unchecked", "rawtypes"})
class ScimFilterParserTest {

    private final UUID workspaceId = UUID.randomUUID();
    private Root<ScimUser> root;
    private CriteriaQuery<?> query;
    private CriteriaBuilder cb;
    private Path path;

    @BeforeEach
    void setUp() {
        root = Mockito.mock(Root.class);
        query = Mockito.mock(CriteriaQuery.class);
        cb = Mockito.mock(CriteriaBuilder.class);
        path = Mockito.mock(Path.class);

        when(root.get(anyString())).thenReturn(path);
        when(path.get(anyString())).thenReturn(path);

        Predicate dummyPredicate = Mockito.mock(Predicate.class);
        when(dummyPredicate.not()).thenReturn(dummyPredicate);
        when(cb.equal(any(), any())).thenReturn(dummyPredicate);
        when(cb.notEqual(any(), any())).thenReturn(dummyPredicate);
        when(cb.like(any(Expression.class), anyString())).thenReturn(dummyPredicate);
        when(cb.like(any(Expression.class), anyString(), anyChar())).thenReturn(dummyPredicate);
        when(cb.notLike(any(Expression.class), anyString())).thenReturn(dummyPredicate);
        when(cb.notLike(any(Expression.class), anyString(), anyChar())).thenReturn(dummyPredicate);
        when(cb.greaterThan(any(Expression.class), any(Comparable.class))).thenReturn(dummyPredicate);
        when(cb.greaterThanOrEqualTo(any(Expression.class), any(Comparable.class))).thenReturn(dummyPredicate);
        when(cb.lessThan(any(Expression.class), any(Comparable.class))).thenReturn(dummyPredicate);
        when(cb.lessThanOrEqualTo(any(Expression.class), any(Comparable.class))).thenReturn(dummyPredicate);
        when(cb.isNotNull(any())).thenReturn(dummyPredicate);
        when(cb.isNull(any())).thenReturn(dummyPredicate);
        when(cb.not(any())).thenReturn(dummyPredicate);
        when(cb.and(any(), any())).thenReturn(dummyPredicate);
        when(cb.or(any(), any())).thenReturn(dummyPredicate);
        when(cb.lower(any())).thenReturn((Expression) path);
        when(path.as(String.class)).thenReturn((Expression) path);
    }

    @Test
    void testParseUserFilter_Empty() {
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(null, workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
        verify(cb).equal(any(), eq(workspaceId));
    }

    @Test
    void testParseUserFilter_ComplexAndOrNot_Grouping() {
        String filter = "(userName eq \"test\" or name.familyName sw \"Smith\") and (meta.created gt \"2023-01-01T00:00:00Z\") and not (title pr)";
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);
        // By calling toPredicate, we fire all lambda branches
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }
    
    @Test
    void testOperators() {
        String[] ops = {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"};
        for (String op : ops) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter("userName " + op + " \"test\"", workspaceId);
            assertNotNull(spec);
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testUserAttributes() {
        String[] attrs = {
            "meta.created", "meta.lastModified", "name.familyName", "name.givenName", 
            "name.formatted", "name.middleName", "name.honorificPrefix", "name.honorificSuffix", 
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", 
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter", 
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization", 
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division", 
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", 
            "id", "userName", "externalId", "displayName", "nickName", "title", "userType", 
            "profileUrl", "preferredLanguage", "locale", "timezone", "active"
        };
        for (String attr : attrs) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " pr", workspaceId);
            assertNotNull(spec);
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testGroupAttributes() {
        String[] attrs = {"meta.created", "meta.lastModified", "id", "displayName", "externalId"};
        for (String attr : attrs) {
            Specification<ScimGroup> spec = ScimFilterParser.parseGroupFilter(attr + " eq \"test\"", workspaceId);
            assertNotNull(spec);
            spec.toPredicate((Root) root, query, cb);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "active eq true",
            "emails.value eq \"test@example.com\"",
            "phoneNumbers.type eq \"work\"",
            "urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\"",
            "emails[type eq \"work\" and value co \"@example.com\"]",
            "Emails[Type eq \"work\"]",
            "emails.value pr",
            "emails.primary eq true"
    })
    void testSupportedUserFilters(String filter) {
        ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, true);
        assertNotNull(ast);
        if (ScimFilterParser.requiresInMemoryEvaluation(ast, true)) {
            Specification<ScimUser> preFilter = ScimFilterParser.buildUserPreFilter(ast, workspaceId);
            assertNotNull(preFilter);
            preFilter.toPredicate(root, query, cb);
        } else {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);
            assertNotNull(spec);
            spec.toPredicate(root, query, cb);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "urn:ietf:params:scim:schemas:core:2.0:Group:displayName eq \"test\""
    })
    void testSupportedGroupFilters(String filter) {
        Specification<ScimGroup> spec = ScimFilterParser.parseGroupFilter(filter, workspaceId);
        assertNotNull(spec);
        spec.toPredicate((Root) root, query, cb);
    }

    @Test
    void testInvalid() {
        Specification<ScimUser> specOp = ScimFilterParser.parseUserFilter("userName unknownOp \"test\"", workspaceId);
        assertThrows(ScimException.class, () -> specOp.toPredicate(root, query, cb));

        assertThrows(ScimException.class, () -> ScimFilterParser.parseUserFilter("(userName eq \"test\"", workspaceId));
        
        // Ensure that exceptions inside toPredicate are triggered correctly
        Specification<ScimUser> specAttr = ScimFilterParser.parseUserFilter("meta.unknown pr", workspaceId);
        assertThrows(ScimException.class, () -> specAttr.toPredicate(root, query, cb));
        
        Specification<ScimUser> specAttr2 = ScimFilterParser.parseUserFilter("name.unknown pr", workspaceId);
        assertThrows(ScimException.class, () -> specAttr2.toPredicate(root, query, cb));
        
        Specification<ScimUser> specAttr3 = ScimFilterParser.parseUserFilter("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:unknown pr", workspaceId);
        assertThrows(ScimException.class, () -> specAttr3.toPredicate(root, query, cb));
        
        Specification<ScimUser> specAttr4 = ScimFilterParser.parseUserFilter("unknownAttr pr", workspaceId);
        assertThrows(ScimException.class, () -> specAttr4.toPredicate(root, query, cb));
    }

    @Test
    void testResolveSort() {
        assertEquals("userName", ScimFilterParser.resolveUserSortAttribute(null));
        assertEquals("userName", ScimFilterParser.resolveUserSortAttribute("userName"));
        assertEquals("nameFamilyName", ScimFilterParser.resolveUserSortAttribute("name.familyName"));
        assertEquals("nameGivenName", ScimFilterParser.resolveUserSortAttribute("name.givenName"));
        assertEquals("displayName", ScimFilterParser.resolveUserSortAttribute("displayName"));
        assertEquals("title", ScimFilterParser.resolveUserSortAttribute("title"));
        assertEquals("externalId", ScimFilterParser.resolveUserSortAttribute("externalId"));
        assertEquals("createdAt", ScimFilterParser.resolveUserSortAttribute("meta.created"));
        assertEquals("lastModified", ScimFilterParser.resolveUserSortAttribute("meta.lastModified"));
        assertEquals("id", ScimFilterParser.resolveUserSortAttribute("id"));

        // Emails sorting resolution (RFC 7644 §3.4.2.3 R5)
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("emails"));
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("emails.value"));
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("Emails"));
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("EMAILS.VALUE"));
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("urn:ietf:params:scim:schemas:core:2.0:User:emails"));
        assertEquals("emails", ScimFilterParser.resolveUserSortAttribute("urn:ietf:params:scim:schemas:core:2.0:User:emails.value"));

        // Core URN prefix stripping
        assertEquals("title", ScimFilterParser.resolveUserSortAttribute("urn:ietf:params:scim:schemas:core:2.0:User:title"));
        assertEquals("displayName", ScimFilterParser.resolveGroupSortAttribute("urn:ietf:params:scim:schemas:core:2.0:Group:displayName"));

        // Unsupported multi-valued sorting throws 400 invalidValue
        assertThrows(ScimException.class, () -> ScimFilterParser.resolveUserSortAttribute("roles"));
        assertThrows(ScimException.class, () -> ScimFilterParser.resolveUserSortAttribute("addresses"));
        assertThrows(ScimException.class, () -> ScimFilterParser.resolveUserSortAttribute("phoneNumbers"));
        assertThrows(ScimException.class, () -> ScimFilterParser.resolveUserSortAttribute("emails.type"));

        assertEquals("displayName", ScimFilterParser.resolveGroupSortAttribute(null));
        assertEquals("displayName", ScimFilterParser.resolveGroupSortAttribute("displayName"));
        assertEquals("externalId", ScimFilterParser.resolveGroupSortAttribute("externalId"));
        assertEquals("createdAt", ScimFilterParser.resolveGroupSortAttribute("meta.created"));
        assertEquals("lastModified", ScimFilterParser.resolveGroupSortAttribute("meta.lastModified"));
        assertEquals("id", ScimFilterParser.resolveGroupSortAttribute("id"));
    }

    // ── RFC 7644 §3.4.2.2 Conformance Tests ──────────────────────────────

    @Test
    void testCaseInsensitiveAttributeNames() {
        // RFC 7644 §3.4.2.2: "Attribute names and attribute operators used in filters are case insensitive"
        String[] variants = {"UserName", "USERNAME", "username", "userName"};
        for (String attr : variants) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " eq \"test\"", workspaceId);
            assertNotNull(spec, "Filter with attribute '" + attr + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testCaseInsensitiveNameSubAttributes() {
        // RFC 7644 §3.4.2.2: name.* sub-attributes must be case insensitive
        String[] variants = {"Name.FamilyName", "NAME.FAMILYNAME", "name.familyname"};
        for (String attr : variants) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " eq \"test\"", workspaceId);
            assertNotNull(spec, "Filter with attribute '" + attr + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testCaseInsensitiveMetaAttributes() {
        // RFC 7644 §3.4.2.2: meta.* sub-attributes must be case insensitive
        String[] variants = {"Meta.Created", "META.LASTMODIFIED", "meta.lastModified"};
        for (String attr : variants) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " pr", workspaceId);
            assertNotNull(spec, "Filter with attribute '" + attr + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testCaseInsensitiveEnterpriseAttributes() {
        // RFC 7644 §3.4.2.2: Enterprise extension URN attributes must be case insensitive
        String prefix = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:";
        String[] variants = {
            prefix + "User:employeeNumber",
            prefix + "user:EmployeeNumber",
            prefix + "USER:EMPLOYEENUMBER"
        };
        for (String attr : variants) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " pr", workspaceId);
            assertNotNull(spec, "Filter with attribute '" + attr + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testCaseInsensitiveGroupAttributes() {
        // RFC 7644 §3.4.2.2: Group attribute names must also be case insensitive
        String[] variants = {"DisplayName", "DISPLAYNAME", "displayname", "ExternalId", "EXTERNALID"};
        for (String attr : variants) {
            Specification<ScimGroup> spec = ScimFilterParser.parseGroupFilter(attr + " eq \"test\"", workspaceId);
            assertNotNull(spec, "Group filter with attribute '" + attr + "' should parse successfully");
            spec.toPredicate((Root) root, query, cb);
        }
    }

    @Test
    void testCaseInsensitiveOperators() {
        // RFC 7644 §3.4.2.2: "attribute operators used in filters are case insensitive"
        String[] ops = {"EQ", "Eq", "eQ", "NE", "CO", "SW", "EW", "PR", "GT", "GE", "LT", "LE"};
        for (String op : ops) {
            String filter = "pr".equalsIgnoreCase(op) ? "userName " + op : "userName " + op + " \"test\"";
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);
            assertNotNull(spec, "Filter with operator '" + op + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testCoreSchemaUrnPrefixCaseInsensitive() {
        // URN prefix with different casing
        String[] prefixes = {
            "urn:ietf:params:scim:schemas:core:2.0:User:userName",
            "urn:ietf:params:scim:schemas:core:2.0:user:username",
            "URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:USERNAME"
        };
        for (String attr : prefixes) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(attr + " eq \"test\"", workspaceId);
            assertNotNull(spec, "Filter with URN '" + attr + "' should parse successfully");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testValuePathFilterCombinedWithOuterFilter() {
        // RFC 7644 §3.4.2.2 example: userType eq "Employee" and emails[type eq "work" and value co "@example.com"]
        String filter = "userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]";
        ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, true);
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(ast, true));
        Specification<ScimUser> spec = ScimFilterParser.buildUserPreFilter(ast, workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }

    @Test
    void testValuePathFilterOrCombination() {
        // RFC 7644 §3.4.2.2 example: emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]
        String filter = "emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]";
        ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, true);
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(ast, true));
        Specification<ScimUser> spec = ScimFilterParser.buildUserPreFilter(ast, workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }

    @Test
    void testJsonCollectionAllOperators() {
        // Test all supported operators on JSON collections via AST + pre-filter + evaluator
        String[] ops = {"eq", "ne", "co", "sw", "ew"};
        for (String op : ops) {
            String filter = "emails.value " + op + " \"test@example.com\"";
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(filter, true);
            assertNotNull(ast, "JSON collection filter with operator '" + op + "' should parse");
            Specification<ScimUser> spec = ScimFilterParser.buildUserPreFilter(ast, workspaceId);
            assertNotNull(spec);
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testJsonCollectionUnsupportedOperator() {
        // gt/ge/lt/le on JSON collections should throw in parseAst
        assertThrows(ScimException.class, () -> ScimFilterParser.parseAst("emails.value gt \"test\"", true));
    }

    @Test
    void testActiveBooleanOnlySupportsEqAndNe() {
        Path activePath = Mockito.mock(Path.class);
        when(activePath.getJavaType()).thenReturn(Boolean.class);
        when(root.get("active")).thenReturn(activePath);

        Specification<ScimUser> eqSpec = ScimFilterParser.parseUserFilter("active eq true", workspaceId);
        assertNotNull(eqSpec);
        eqSpec.toPredicate(root, query, cb);

        Specification<ScimUser> neSpec = ScimFilterParser.parseUserFilter("active ne false", workspaceId);
        assertNotNull(neSpec);
        neSpec.toPredicate(root, query, cb);

        Specification<ScimUser> gtSpec = ScimFilterParser.parseUserFilter("active gt true", workspaceId);
        ScimException ex = assertThrows(ScimException.class, () -> gtSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());
    }

    @Test
    void testMalformedDateTimeInFilterThrows() {
        Path datePath = Mockito.mock(Path.class);
        when(datePath.getJavaType()).thenReturn(java.time.Instant.class);
        when(root.get("lastModified")).thenReturn(datePath);

        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter("meta.lastModified gt \"not-an-iso-8601-date\"", workspaceId);
        ScimException ex = assertThrows(ScimException.class, () -> spec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        // Date-only string lacks required time component per RFC 7643 §2.3.5
        Specification<ScimUser> dateOnlySpec = ScimFilterParser.parseUserFilter("meta.lastModified gt \"2026-01-01\"", workspaceId);
        ScimException exDateOnly = assertThrows(ScimException.class, () -> dateOnlySpec.toPredicate(root, query, cb));
        assertEquals(400, exDateOnly.getHttpStatus());
        assertEquals("invalidFilter", exDateOnly.getScimType());
    }

    @Test
    void testValidDateTimeInFilterSucceeds() {
        Path datePath = Mockito.mock(Path.class);
        when(datePath.getJavaType()).thenReturn(java.time.Instant.class);
        when(root.get("lastModified")).thenReturn(datePath);

        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter("meta.lastModified gt \"2026-01-01T00:00:00Z\"", workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }

    @Test
    void testDateTimeEqNeAndSubstringRejection() {
        Path datePath = Mockito.mock(Path.class);
        when(datePath.getJavaType()).thenReturn(java.time.Instant.class);
        when(root.get("createdAt")).thenReturn(datePath);
        when(root.get("lastModified")).thenReturn(datePath);

        Specification<ScimUser> eqSpec = ScimFilterParser.parseUserFilter("meta.created eq \"2026-01-01T00:00:00Z\"", workspaceId);
        assertNotNull(eqSpec);
        eqSpec.toPredicate(root, query, cb);
        verify(cb).equal(eq(datePath), any(java.time.Instant.class));

        Specification<ScimUser> neSpec = ScimFilterParser.parseUserFilter("meta.lastModified ne \"2026-01-01T00:00:00Z\"", workspaceId);
        assertNotNull(neSpec);
        neSpec.toPredicate(root, query, cb);
        verify(cb).notEqual(eq(datePath), any(java.time.Instant.class));

        // Substrings on dateTime must be rejected
        Specification<ScimUser> coSpec = ScimFilterParser.parseUserFilter("meta.created co \"2026\"", workspaceId);
        ScimException ex = assertThrows(ScimException.class, () -> coSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        Specification<ScimUser> swSpec = ScimFilterParser.parseUserFilter("meta.lastModified sw \"2026\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> swSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());

        Specification<ScimUser> ewSpec = ScimFilterParser.parseUserFilter("meta.lastModified ew \"2026\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> ewSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
    }

    @Test
    void testActiveInvalidBooleanValueThrows() {
        Path activePath = Mockito.mock(Path.class);
        when(activePath.getJavaType()).thenReturn(Boolean.class);
        when(root.get("active")).thenReturn(activePath);

        Specification<ScimUser> eqYes = ScimFilterParser.parseUserFilter("active eq \"yes\"", workspaceId);
        ScimException ex = assertThrows(ScimException.class, () -> eqYes.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        Specification<ScimUser> neFoo = ScimFilterParser.parseUserFilter("active ne \"foo\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> neFoo.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());
    }

    @Test
    void testStringAttributeWithValueTrueIsNotCoercedToBoolean() {
        Path userPath = Mockito.mock(Path.class);
        when(userPath.getJavaType()).thenReturn(String.class);
        when(root.get("userName")).thenReturn(userPath);

        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter("userName eq \"true\"", workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
        // Verify cb.equal was invoked with String value "true", never boolean true
        verify(cb, never()).equal(any(), eq(Boolean.TRUE));
        verify(cb).equal(any(), eq("true"));
    }

    @Test
    void testUuidAttributeRejectsSubstringsAndOrder() {
        Path idPath = Mockito.mock(Path.class);
        when(idPath.getJavaType()).thenReturn(UUID.class);
        when(root.get("id")).thenReturn(idPath);

        Specification<ScimUser> coSpec = ScimFilterParser.parseUserFilter("id co \"123\"", workspaceId);
        ScimException ex = assertThrows(ScimException.class, () -> coSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        Specification<ScimUser> swSpec = ScimFilterParser.parseUserFilter("id sw \"123\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> swSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        Specification<ScimUser> ewSpec = ScimFilterParser.parseUserFilter("id ew \"123\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> ewSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        Specification<ScimUser> gtSpec = ScimFilterParser.parseUserFilter("id gt \"123\"", workspaceId);
        ex = assertThrows(ScimException.class, () -> gtSpec.toPredicate(root, query, cb));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());
    }

    @Test
    void testUuidAttributeEqNeWithValidAndInvalidUUID() {
        Path idPath = Mockito.mock(Path.class);
        when(idPath.getJavaType()).thenReturn(UUID.class);
        when(root.get("id")).thenReturn(idPath);

        UUID testUuid = UUID.randomUUID();
        Specification<ScimUser> eqValid = ScimFilterParser.parseUserFilter("id eq \"" + testUuid + "\"", workspaceId);
        assertNotNull(eqValid);
        eqValid.toPredicate(root, query, cb);
        verify(cb).equal(eq(idPath), eq(testUuid));

        Specification<ScimUser> eqInvalid = ScimFilterParser.parseUserFilter("id eq \"not-a-uuid\"", workspaceId);
        ScimException exEq = assertThrows(ScimException.class, () -> eqInvalid.toPredicate(root, query, cb));
        assertEquals(400, exEq.getHttpStatus());
        assertEquals("invalidFilter", exEq.getScimType());

        // Lenient UUID formats like "1-1-1-1-1" must also be rejected per strict RFC 4122 textual form
        Specification<ScimUser> eqLenient = ScimFilterParser.parseUserFilter("id eq \"1-1-1-1-1\"", workspaceId);
        ScimException exLenient = assertThrows(ScimException.class, () -> eqLenient.toPredicate(root, query, cb));
        assertEquals(400, exLenient.getHttpStatus());
        assertEquals("invalidFilter", exLenient.getScimType());

        Specification<ScimUser> neInvalid = ScimFilterParser.parseUserFilter("id ne \"not-a-uuid\"", workspaceId);
        ScimException exNe = assertThrows(ScimException.class, () -> neInvalid.toPredicate(root, query, cb));
        assertEquals(400, exNe.getHttpStatus());
        assertEquals("invalidFilter", exNe.getScimType());
    }

    @Test
    void testMetaResourceTypeFilter() {
        Predicate mockTrue = Mockito.mock(Predicate.class);
        Predicate mockFalse = Mockito.mock(Predicate.class);
        when(cb.conjunction()).thenReturn(mockTrue);
        when(cb.disjunction()).thenReturn(mockFalse);

        // User filter
        Specification<ScimUser> userEqUser = ScimFilterParser.parseUserFilter("meta.resourceType eq \"User\"", workspaceId);
        assertNotNull(userEqUser);
        userEqUser.toPredicate(root, query, cb);

        Specification<ScimUser> userEqGroup = ScimFilterParser.parseUserFilter("meta.resourceType eq \"Group\"", workspaceId);
        assertNotNull(userEqGroup);
        userEqGroup.toPredicate(root, query, cb);

        Specification<ScimUser> userPr = ScimFilterParser.parseUserFilter("meta.resourceType pr", workspaceId);
        assertNotNull(userPr);
        userPr.toPredicate(root, query, cb);

        // Group filter
        Root<ScimGroup> groupRoot = Mockito.mock(Root.class);
        Path groupWsPath = Mockito.mock(Path.class);
        Path groupWsIdPath = Mockito.mock(Path.class);
        when(groupRoot.get("workspace")).thenReturn(groupWsPath);
        when(groupWsPath.get("id")).thenReturn(groupWsIdPath);

        Specification<ScimGroup> groupEqGroup = ScimFilterParser.parseGroupFilter("meta.resourceType eq \"Group\"", workspaceId);
        assertNotNull(groupEqGroup);
        groupEqGroup.toPredicate(groupRoot, query, cb);

        Specification<ScimGroup> groupEqUser = ScimFilterParser.parseGroupFilter("meta.resourceType eq \"User\"", workspaceId);
        assertNotNull(groupEqUser);
        groupEqUser.toPredicate(groupRoot, query, cb);
    }

    @Test
    void testContainsValuePathAndSortCaseExact() {
        assertTrue(ScimFilterParser.containsValuePath("emails[type eq \"work\"]"));
        assertFalse(ScimFilterParser.containsValuePath("userName eq \"a[b]c\""));
        assertFalse(ScimFilterParser.containsValuePath(null));

        assertTrue(ScimFilterParser.isSortByCaseExact("externalId"));
        assertTrue(ScimFilterParser.isSortByCaseExact("profileUrl"));
        assertTrue(ScimFilterParser.isSortByCaseExact("id"));
        assertFalse(ScimFilterParser.isSortByCaseExact("userName"));
        assertFalse(ScimFilterParser.isSortByCaseExact("displayName"));
    }

    @Test
    void testTopLevelCollectionPresenceAndCrossResourceAbsence() {
        Predicate mockFalse = Mockito.mock(Predicate.class);
        when(cb.disjunction()).thenReturn(mockFalse);

        String[] collectionPr = {"emails pr", "phoneNumbers pr", "name pr",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User pr",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager pr",
                "members pr"};
        for (String f : collectionPr) {
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(f, true);
            Specification<ScimUser> spec = ScimFilterParser.requiresInMemoryEvaluation(ast, true)
                    ? ScimFilterParser.buildUserPreFilter(ast, workspaceId)
                    : ScimFilterParser.parseUserFilter(f, workspaceId);
            assertNotNull(spec);
            spec.toPredicate(root, query, cb);
        }

        Root<ScimGroup> groupRoot = Mockito.mock(Root.class);
        Path groupWsPath = Mockito.mock(Path.class);
        Path groupWsIdPath = Mockito.mock(Path.class);
        when(groupRoot.get("workspace")).thenReturn(groupWsPath);
        when(groupWsPath.get("id")).thenReturn(groupWsIdPath);

        Specification<ScimGroup> crossGroup = ScimFilterParser.parseGroupFilter("userName eq \"alice\"", workspaceId);
        assertNotNull(crossGroup);
        crossGroup.toPredicate(groupRoot, query, cb);
    }

    @Test
    void testGroupsAndMembersPreFilterPushDown() {
        Subquery<UUID> subquery = Mockito.mock(Subquery.class);
        Root membershipRoot = Mockito.mock(Root.class);
        Predicate existsPred = Mockito.mock(Predicate.class);
        when(query.subquery(UUID.class)).thenReturn(subquery);
        when(subquery.from(any(Class.class))).thenReturn(membershipRoot);
        when(membershipRoot.get(anyString())).thenReturn(path);
        when(cb.exists(subquery)).thenReturn(existsPred);

        UUID groupId = UUID.randomUUID();
        String[] userGroupFilters = {
                "groups pr",
                "groups.display eq \"Admins\"",
                "groups.value eq \"" + groupId + "\"",
                "groups eq \"" + groupId + "\"",
                "groups[display co \"Admin\"]"
        };
        for (String f : userGroupFilters) {
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(f, true);
            Specification<ScimUser> preFilter = ScimFilterParser.buildUserPreFilter(ast, workspaceId);
            preFilter.toPredicate(root, query, cb);
        }
        verify(cb, times(userGroupFilters.length)).exists(subquery);

        UUID memberId = UUID.randomUUID();
        Root<ScimGroup> groupRoot = Mockito.mock(Root.class);
        when(groupRoot.get(anyString())).thenReturn(path);
        String[] groupMemberFilters = {
                "members pr",
                "members.display eq \"Alice\"",
                "members.value eq \"" + memberId + "\"",
                "members eq \"" + memberId + "\"",
                "members.type eq \"User\"",
                "members[value eq \"" + memberId + "\"]"
        };
        for (String f : groupMemberFilters) {
            ScimFilterParser.FilterNode ast = ScimFilterParser.parseAst(f, false);
            Specification<ScimGroup> preFilter = ScimFilterParser.buildGroupPreFilter(ast, workspaceId);
            preFilter.toPredicate(groupRoot, query, cb);
        }
        verify(cb, times(userGroupFilters.length + groupMemberFilters.length)).exists(subquery);
    }

    @Test
    void testRequiresInMemoryEvaluationAndReferencesUserGroups() {
        assertFalse(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("userName eq \"alice\" and active eq true", true), true));
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("emails.type eq \"work\"", true), true));
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("emails[type eq \"work\"]", true), true));
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("schemas eq \"urn:ietf:params:scim:schemas:core:2.0:User\"", true), true));
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("members eq \"" + UUID.randomUUID() + "\"", true), true));

        assertFalse(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("displayName eq \"Devs\"", false), false));
        assertTrue(ScimFilterParser.requiresInMemoryEvaluation(
                ScimFilterParser.parseAst("members.type ne \"User\"", false), false));

        assertFalse(ScimFilterParser.referencesUserGroups(
                ScimFilterParser.parseAst("userName eq \"alice\" and emails[type eq \"work\"]", true)));
        assertTrue(ScimFilterParser.referencesUserGroups(
                ScimFilterParser.parseAst("groups.display eq \"Admins\"", true)));
        assertTrue(ScimFilterParser.referencesUserGroups(
                ScimFilterParser.parseAst("groups[display eq \"Admins\"]", true)));
    }

    @Test
    void testFilterGuardrails_MaxLengthMaxTokensAndMaxDepthReturn400InvalidFilter() {
        // 1. Nesting depth <= 20 succeeds
        String validNested = "(".repeat(20) + "userName eq \"alice\"" + ")".repeat(20);
        assertNotNull(ScimFilterParser.parseAst(validNested, true));
        assertNotNull(ScimFilterParser.parseUserFilter(validNested, workspaceId));

        // 2. Parenthesis nesting > 20 throws 400 invalidFilter (never StackOverflowError)
        String deepParens = "(".repeat(25) + "userName eq \"alice\"" + ")".repeat(25);
        ScimException parenAstEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst(deepParens, true));
        assertEquals(400, parenAstEx.getHttpStatus());
        assertEquals("invalidFilter", parenAstEx.getScimType());

        ScimException parenSpecEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseUserFilter(deepParens, workspaceId));
        assertEquals(400, parenSpecEx.getHttpStatus());
        assertEquals("invalidFilter", parenSpecEx.getScimType());

        ScimException parenGroupEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseGroupFilter("(".repeat(25) + "displayName eq \"g\"" + ")".repeat(25), workspaceId));
        assertEquals(400, parenGroupEx.getHttpStatus());
        assertEquals("invalidFilter", parenGroupEx.getScimType());

        // 3. Chained 'not' recursion > 20 throws 400 invalidFilter
        String deepNot = "not ".repeat(25) + "userName pr";
        ScimException notAstEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst(deepNot, true));
        assertEquals(400, notAstEx.getHttpStatus());
        assertEquals("invalidFilter", notAstEx.getScimType());

        ScimException notSpecEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseUserFilter(deepNot, workspaceId));
        assertEquals(400, notSpecEx.getHttpStatus());
        assertEquals("invalidFilter", notSpecEx.getScimType());

        // 4. Deeply nested valuePath inner filter throws 400 invalidFilter
        String deepValuePath = "emails[" + "(".repeat(22) + "type eq \"work\"" + ")".repeat(22) + "]";
        ScimException vpEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst(deepValuePath, true));
        assertEquals(400, vpEx.getHttpStatus());
        assertEquals("invalidFilter", vpEx.getScimType());

        // 5. 51-term and 100-term 'id eq "<uuid>"' OR filters succeed in both parseAst and parseUserFilter
        String orFilter51 = buildIdOrFilter(51);
        assertNotNull(ScimFilterParser.parseAst(orFilter51, true));
        assertNotNull(ScimFilterParser.parseUserFilter(orFilter51, workspaceId));

        String orFilter100 = buildIdOrFilter(100);
        assertNotNull(ScimFilterParser.parseAst(orFilter100, true));
        assertNotNull(ScimFilterParser.parseUserFilter(orFilter100, workspaceId));

        // 6. Filter exceeding max length (16,384 chars) throws 400 invalidFilter
        String oversizedFilter = "userName eq \"" + "a".repeat(ScimFilterParser.MAX_FILTER_LENGTH) + "\"";
        ScimException lenEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst(oversizedFilter, true));
        assertEquals(400, lenEx.getHttpStatus());
        assertEquals("invalidFilter", lenEx.getScimType());
        assertTrue(lenEx.getMessage().contains(String.valueOf(ScimFilterParser.MAX_FILTER_LENGTH)));

        // 7. Filter exceeding max tokens (2,000 tokens, while well under 16,384 chars) throws 400 invalidFilter
        StringBuilder manyTokens = new StringBuilder("id pr");
        for (int i = 0; i < 670; i++) {
            manyTokens.append(" or id pr"); // +3 tokens per iteration -> 2,012 tokens total (~6,035 chars)
        }
        String manyTokensStr = manyTokens.toString();
        assertTrue(manyTokensStr.length() < ScimFilterParser.MAX_FILTER_LENGTH);
        ScimException tokEx = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst(manyTokensStr, true));
        assertEquals(400, tokEx.getHttpStatus());
        assertEquals("invalidFilter", tokEx.getScimType());
        assertTrue(tokEx.getMessage().contains(String.valueOf(ScimFilterParser.MAX_FILTER_TOKENS)));
    }

    private static String buildIdOrFilter(int termCount) {
        StringBuilder sb = new StringBuilder(termCount * 48);
        for (int i = 0; i < termCount; i++) {
            if (i > 0) {
                sb.append(" or ");
            }
            sb.append("id eq \"").append(UUID.randomUUID()).append('"');
        }
        return sb.toString();
    }
}
