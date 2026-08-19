package de.palsoftware.scim.server.impl.controller;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The base URL built here becomes the authority of every {@code meta.location} and {@code $ref} in a
 * SCIM response, so it must not be steerable by the caller. The edge in front of this service strips
 * X-Forwarded-Host and X-Forwarded-Port, but that is dashboard configuration which any infrastructure
 * rebuild can lose - these tests are the copy that cannot be lost.
 */
class ScimBaseControllerTest {

    private static final String WORKSPACE_ID = "24fb7ccb-3458-44da-b5c8-92b97e2ad702";

    @Test
    void ignoresSpoofedForwardedHostAndPort() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + WORKSPACE_ID + "/scim/v2/Users");
        request.setServerName("api2.scimsandbox.net");
        request.setServerPort(80);
        request.addHeader("X-Forwarded-Proto", "https");
        request.addHeader("X-Forwarded-Host", "evil.example");
        request.addHeader("X-Forwarded-Port", "1337");

        assertEquals("https://api2.scimsandbox.net/ws/" + WORKSPACE_ID + "/scim/v2",
                ScimBaseController.buildBaseUrl(request, WORKSPACE_ID));
    }

    @Test
    void usesForwardedProtoForScheme() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + WORKSPACE_ID + "/scim/v2/Users");
        request.setServerName("api2.scimsandbox.net");
        request.setServerPort(80);
        request.setScheme("http");
        request.addHeader("X-Forwarded-Proto", "https");

        assertEquals("https://api2.scimsandbox.net/ws/" + WORKSPACE_ID + "/scim/v2",
                ScimBaseController.buildBaseUrl(request, WORKSPACE_ID));
    }

    @Test
    void keepsNonDefaultPortFromTheRequestItself() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + WORKSPACE_ID + "/scim/v2/Users");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setScheme("http");

        assertEquals("http://localhost:8080/ws/" + WORKSPACE_ID + "/scim/v2",
                ScimBaseController.buildBaseUrl(request, WORKSPACE_ID));
    }

    @Test
    void appendsCompatSegmentWhenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ws/" + WORKSPACE_ID + "/scim/v2/v2/Users");
        request.setServerName("api2.scimsandbox.net");
        request.setServerPort(80);
        request.addHeader("X-Forwarded-Proto", "https");

        assertEquals("https://api2.scimsandbox.net/ws/" + WORKSPACE_ID + "/scim/v2/v2",
                ScimBaseController.buildBaseUrl(request, WORKSPACE_ID, "v2"));
    }
}
