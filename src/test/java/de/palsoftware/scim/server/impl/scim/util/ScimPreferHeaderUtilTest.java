package de.palsoftware.scim.server.impl.scim.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

class ScimPreferHeaderUtilTest {

    @Test
    void testNullOrEmptyString() {
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync((String) null));
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync(""));
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync("   "));
    }

    @Test
    void testSingleRespondAsync() {
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("respond-async"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("  respond-async  "));
    }

    @Test
    void testCaseInsensitive() {
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("Respond-Async"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("RESPOND-ASYNC"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("respond-ASYNC"));
    }

    @Test
    void testCommaSeparated() {
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("return=minimal, respond-async"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("respond-async, wait=10"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("handling=lenient, respond-async, return=representation"));
    }

    @Test
    void testWithParameters() {
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("respond-async;wait=100"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("respond-async; wait=10"));
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync("return=minimal, respond-async;wait=50"));
    }

    @Test
    void testDifferentToken() {
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync("respond-async-other"));
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync("wait=10"));
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync("return=representation"));
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync("custom-respond-async"));
    }

    @Test
    void testHttpServletRequest() {
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync((MockHttpServletRequest) null));

        MockHttpServletRequest reqEmpty = new MockHttpServletRequest();
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync(reqEmpty));

        MockHttpServletRequest reqSingle = new MockHttpServletRequest();
        reqSingle.addHeader("Prefer", "respond-async");
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync(reqSingle));

        MockHttpServletRequest reqMultiple = new MockHttpServletRequest();
        reqMultiple.addHeader("Prefer", "return=minimal");
        reqMultiple.addHeader("Prefer", "respond-async;wait=10");
        assertTrue(ScimPreferHeaderUtil.hasRespondAsync(reqMultiple));

        MockHttpServletRequest reqOther = new MockHttpServletRequest();
        reqOther.addHeader("Prefer", "return=minimal");
        assertFalse(ScimPreferHeaderUtil.hasRespondAsync(reqOther));
    }

    @Test
    void testWaitPreferenceAndShouldExecuteAsync() {
        MockHttpServletRequest reqAsyncOnly = new MockHttpServletRequest();
        reqAsyncOnly.addHeader("Prefer", "respond-async");
        assertTrue(ScimPreferHeaderUtil.getWaitSeconds(reqAsyncOnly).isEmpty());
        assertTrue(ScimPreferHeaderUtil.shouldExecuteAsync(reqAsyncOnly));
        assertEquals("respond-async", ScimPreferHeaderUtil.buildPreferenceAppliedHeader(reqAsyncOnly));

        MockHttpServletRequest reqWait10Comma = new MockHttpServletRequest();
        reqWait10Comma.addHeader("Prefer", "respond-async, wait=10");
        assertEquals(10, ScimPreferHeaderUtil.getWaitSeconds(reqWait10Comma).orElse(-1));
        assertFalse(ScimPreferHeaderUtil.shouldExecuteAsync(reqWait10Comma));

        MockHttpServletRequest reqWait10Semi = new MockHttpServletRequest();
        reqWait10Semi.addHeader("Prefer", "respond-async; wait=10");
        assertEquals(10, ScimPreferHeaderUtil.getWaitSeconds(reqWait10Semi).orElse(-1));
        assertFalse(ScimPreferHeaderUtil.shouldExecuteAsync(reqWait10Semi));

        MockHttpServletRequest reqWaitZero = new MockHttpServletRequest();
        reqWaitZero.addHeader("Prefer", "respond-async, wait=0");
        assertEquals(0, ScimPreferHeaderUtil.getWaitSeconds(reqWaitZero).orElse(-1));
        assertTrue(ScimPreferHeaderUtil.shouldExecuteAsync(reqWaitZero));
        assertEquals("respond-async, wait=0", ScimPreferHeaderUtil.buildPreferenceAppliedHeader(reqWaitZero));
    }
}
