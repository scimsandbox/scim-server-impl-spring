package de.palsoftware.scim.server.impl.scim.filter;

import de.palsoftware.scim.server.impl.model.ScimGroup;
import de.palsoftware.scim.server.impl.model.ScimGroupMembership;
import de.palsoftware.scim.server.impl.model.ScimUser;
import de.palsoftware.scim.server.impl.model.ScimUserEmail;
import de.palsoftware.scim.server.impl.model.ScimUserPhoneNumber;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.filter.ScimFilterParser.FilterNode;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ScimFilterEvaluatorTest {

    @Test
    void evaluateUser_sameElementValuePath_rejectsCrossElementMatch() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("alice");

        ScimUserEmail workEmail = new ScimUserEmail();
        workEmail.setValue("work@other.org");
        workEmail.setType("work");
        workEmail.setPrimaryFlag(true);

        ScimUserEmail homeEmail = new ScimUserEmail();
        homeEmail.setValue("alice@example.com");
        homeEmail.setType("home");
        homeEmail.setPrimaryFlag(false);

        user.setEmails(List.of(workEmail, homeEmail));

        FilterNode ast = ScimFilterParser.parseAst(
                "emails[type eq \"work\" and value co \"@example.com\"]", true);
        ScimFilterEvaluator.validateAst(ast, true, null);

        // Neither email has BOTH type=="work" AND value containing "@example.com"
        assertFalse(ScimFilterEvaluator.matchesUser(user, List.of(), ast));

        // Matching element should return true
        FilterNode matchAst = ScimFilterParser.parseAst(
                "emails[type eq \"work\" and value eq \"work@other.org\"]", true);
        ScimFilterEvaluator.validateAst(matchAst, true, null);
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), matchAst));
    }

    @Test
    void evaluateUser_collectionAndComplexPresence() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("bob");
        user.setEmails(List.of());

        ScimUserPhoneNumber phone = new ScimUserPhoneNumber();
        phone.setValue("+12015550123");
        phone.setType("work");
        phone.setPrimaryFlag(true);
        user.setPhoneNumbers(List.of(phone));
        user.setNameFamilyName("Builder");

        FilterNode emailsPr = ScimFilterParser.parseAst("emails pr", true);
        FilterNode phonesPr = ScimFilterParser.parseAst("phoneNumbers pr", true);
        FilterNode namePr = ScimFilterParser.parseAst("name pr", true);
        FilterNode groupsPr = ScimFilterParser.parseAst("groups pr", true);

        assertFalse(ScimFilterEvaluator.matchesUser(user, List.of(), emailsPr));
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), phonesPr));
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), namePr));
        assertFalse(ScimFilterEvaluator.matchesUser(user, List.of(), groupsPr));

        UUID groupId = UUID.randomUUID();
        List<Map<String, Object>> groups = List.of(Map.of("value", groupId.toString(), "display", "Devs", "type", "direct"));
        assertTrue(ScimFilterEvaluator.matchesUser(user, groups, groupsPr));

        FilterNode groupValuePath = ScimFilterParser.parseAst(
                "groups[display eq \"devs\" and value eq \"" + groupId + "\"]", true);
        ScimFilterEvaluator.validateAst(groupValuePath, true, null);
        assertTrue(ScimFilterEvaluator.matchesUser(user, groups, groupValuePath));
    }

    @Test
    void evaluateCrossResourceAttributeAbsence() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("carol");

        // Group-only attribute on User evaluates to false; negated evaluates to true
        FilterNode membersPr = ScimFilterParser.parseAst("members pr", true);
        ScimFilterEvaluator.validateAst(membersPr, true, null);
        assertFalse(ScimFilterEvaluator.matchesUser(user, List.of(), membersPr));

        FilterNode notMembersPr = ScimFilterParser.parseAst("not (members pr)", true);
        ScimFilterEvaluator.validateAst(notMembersPr, true, null);
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), notMembersPr));

        ScimGroup group = new ScimGroup();
        group.setId(UUID.randomUUID());
        group.setDisplayName("Eng");

        // User-only attribute on Group evaluates to false; negated evaluates to true
        FilterNode userNameEq = ScimFilterParser.parseAst("userName eq \"carol\"", false);
        ScimFilterEvaluator.validateAst(userNameEq, false, null);
        assertFalse(ScimFilterEvaluator.matchesGroup(group, userNameEq));

        FilterNode notUserNameEq = ScimFilterParser.parseAst("not (userName eq \"carol\")", false);
        ScimFilterEvaluator.validateAst(notUserNameEq, false, null);
        assertTrue(ScimFilterEvaluator.matchesGroup(group, notUserNameEq));
    }

    @Test
    void evaluateCaseExactAndUnicodeNfcNormalization() {
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("Jörg"); // NFC
        user.setExternalId("EXT-AbC");
        user.setProfileUrl("https://example.com/Users/Jorg");
        user.setCreatedAt(Instant.parse("2026-01-15T10:00:00Z"));

        // NFD literal "Jo\u0308rg" matches NFC "Jörg" case-insensitively on userName
        FilterNode nfdFilter = ScimFilterParser.parseAst("userName eq \"jo\u0308rg\"", true);
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), nfdFilter));

        // externalId and profileUrl are caseExact=true
        assertFalse(ScimFilterEvaluator.matchesUser(
                user, List.of(), ScimFilterParser.parseAst("externalId eq \"ext-abc\"", true)));
        assertTrue(ScimFilterEvaluator.matchesUser(
                user, List.of(), ScimFilterParser.parseAst("externalId eq \"EXT-AbC\"", true)));
        assertFalse(ScimFilterEvaluator.matchesUser(
                user, List.of(), ScimFilterParser.parseAst("profileUrl eq \"https://example.com/users/jorg\"", true)));
    }

    @Test
    void evaluateGroupMembersSameElementValuePath() {
        ScimGroup group = new ScimGroup();
        group.setId(UUID.randomUUID());
        group.setDisplayName("Team");

        UUID userMemberId = UUID.randomUUID();
        UUID groupMemberId = UUID.randomUUID();

        ScimGroupMembership m1 = new ScimGroupMembership();
        m1.setMemberValue(userMemberId);
        m1.setMemberType("User");
        m1.setDisplay("Alice");

        ScimGroupMembership m2 = new ScimGroupMembership();
        m2.setMemberValue(groupMemberId);
        m2.setMemberType("Group");
        m2.setDisplay("SubTeam");

        group.getMembers().add(m1);
        group.getMembers().add(m2);

        // Cross-element mismatch: m1 is User, m2 has groupMemberId
        FilterNode crossMismatch = ScimFilterParser.parseAst(
                "members[type eq \"User\" and value eq \"" + groupMemberId + "\"]", false);
        ScimFilterEvaluator.validateAst(crossMismatch, false, null);
        assertFalse(ScimFilterEvaluator.matchesGroup(group, crossMismatch));

        // Same-element match on m2
        FilterNode sameMatch = ScimFilterParser.parseAst(
                "members[type eq \"Group\" and value eq \"" + groupMemberId + "\"]", false);
        ScimFilterEvaluator.validateAst(sameMatch, false, null);
        assertTrue(ScimFilterEvaluator.matchesGroup(group, sameMatch));
    }

    @Test
    void validateAst_rejectsUnknownAttributesAndInvalidValueTypes() {
        ScimException ex = assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst("emails[unknownSub eq \"x\"]", true));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidFilter", ex.getScimType());

        assertThrows(ScimException.class,
                () -> ScimFilterParser.parseAst("emails[primary eq \"notABool\"]", true));
    }

    @Test
    void evaluateBareMultiValuedValueShorthandAndCrossResourceRootFilter() {
        UUID wsId = UUID.randomUUID();
        UUID memberId = UUID.randomUUID();
        UUID otherId = UUID.randomUUID();

        // Root cross-resource filter: "members eq \"<uuid>\" or userName eq \"alice\""
        assertNotNull(ScimFilterParser.parseUserFilter("members eq \"" + memberId + "\" or userName eq \"alice\"", wsId));
        assertNotNull(ScimFilterParser.parseGroupFilter("members eq \"" + memberId + "\" or userName eq \"alice\"", wsId));

        ScimGroup group = new ScimGroup();
        group.setId(UUID.randomUUID());
        group.setDisplayName("Ops");
        ScimGroupMembership m = new ScimGroupMembership();
        m.setMemberValue(memberId);
        m.setMemberType("User");
        group.getMembers().add(m);

        FilterNode groupRootAst = ScimFilterParser.parseAst(
                "members eq \"" + memberId + "\" or userName eq \"alice\"", false);
        assertTrue(ScimFilterEvaluator.matchesGroup(group, groupRootAst));

        FilterNode groupNonMatchAst = ScimFilterParser.parseAst(
                "members eq \"" + otherId + "\" or userName eq \"alice\"", false);
        assertFalse(ScimFilterEvaluator.matchesGroup(group, groupNonMatchAst));

        // Bare emails eq "..." shorthand on User
        ScimUser user = new ScimUser();
        user.setId(UUID.randomUUID());
        user.setUserName("alice");
        ScimUserEmail email = new ScimUserEmail();
        email.setValue("alice@example.com");
        email.setType("work");
        user.setEmails(List.of(email));

        FilterNode bareEmailAst = ScimFilterParser.parseAst("emails eq \"ALICE@example.com\"", true);
        assertTrue(ScimFilterEvaluator.matchesUser(user, List.of(), bareEmailAst));

        // addresses has no .value sub-attribute; ordering on binary x509Certificates is rejected
        assertThrows(ScimException.class, () -> ScimFilterParser.parseAst("addresses eq \"Main St\"", true));
        assertThrows(ScimException.class, () -> ScimFilterParser.parseAst("x509Certificates gt \"QUJD\"", true));
    }
}
