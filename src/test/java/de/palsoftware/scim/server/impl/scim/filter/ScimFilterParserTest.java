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
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(filter, workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
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
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(
                "userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]", workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }

    @Test
    void testValuePathFilterOrCombination() {
        // RFC 7644 §3.4.2.2 example: emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(
                "emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]", workspaceId);
        assertNotNull(spec);
        spec.toPredicate(root, query, cb);
    }

    @Test
    void testJsonCollectionAllOperators() {
        // Test all supported operators on JSON collections
        String[] ops = {"eq", "ne", "co", "sw", "ew"};
        for (String op : ops) {
            Specification<ScimUser> spec = ScimFilterParser.parseUserFilter(
                    "emails.value " + op + " \"test@example.com\"", workspaceId);
            assertNotNull(spec, "JSON collection filter with operator '" + op + "' should parse");
            spec.toPredicate(root, query, cb);
        }
    }

    @Test
    void testJsonCollectionUnsupportedOperator() {
        // gt/ge/lt/le on JSON collections should throw
        Specification<ScimUser> spec = ScimFilterParser.parseUserFilter("emails.value gt \"test\"", workspaceId);
        assertThrows(ScimException.class, () -> spec.toPredicate(root, query, cb));
    }

}
