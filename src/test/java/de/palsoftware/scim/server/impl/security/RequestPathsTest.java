package de.palsoftware.scim.server.impl.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RequestPathsTest {

    @Test
    void isActuatorUriAndPath_MatchExactRootAndSubpathsOnly() {
        assertThat(RequestPaths.isActuatorPath(null)).isFalse();
        assertThat(RequestPaths.isActuatorUri(null)).isFalse();
        assertThat(RequestPaths.isActuatorUri("")).isFalse();
        assertThat(RequestPaths.isActuatorUri("/actuators")).isFalse();
        assertThat(RequestPaths.isActuatorUri("/ws/123/scim/v2/Users")).isFalse();

        assertThat(RequestPaths.isActuatorUri("/actuator")).isTrue();
        assertThat(RequestPaths.isActuatorUri("/actuator/")).isTrue();
        assertThat(RequestPaths.isActuatorUri("/actuator/health")).isTrue();
        assertThat(RequestPaths.isActuatorUri("/actuator/prometheus")).isTrue();

        assertThat(RequestPaths.isActuatorPath(new MockHttpServletRequest("GET", "/actuator/health"))).isTrue();
        assertThat(RequestPaths.isActuatorPath(new MockHttpServletRequest("GET", "/error"))).isFalse();
    }

    @Test
    void isScimUriAndPath_MatchWorkspaceScimRoutesOnly() {
        assertThat(RequestPaths.isScimPath(null)).isFalse();
        assertThat(RequestPaths.isScimUri(null)).isFalse();
        assertThat(RequestPaths.isScimUri("/actuator/health")).isFalse();
        assertThat(RequestPaths.isScimUri("/ws/123/scim/v20")).isFalse();
        assertThat(RequestPaths.isScimUri("/scim/v2/Users")).isFalse();

        UUID wsId = UUID.randomUUID();
        assertThat(RequestPaths.isScimUri("/ws/" + wsId + "/scim/v2")).isTrue();
        assertThat(RequestPaths.isScimUri("/ws/" + wsId + "/scim/v2/")).isTrue();
        assertThat(RequestPaths.isScimUri("/ws/" + wsId + "/scim/v2/Users")).isTrue();
        assertThat(RequestPaths.isScimPath(new MockHttpServletRequest("GET", "/ws/" + wsId + "/scim/v2/Groups"))).isTrue();
        assertThat(RequestPaths.isScimPath(new MockHttpServletRequest("GET", "/actuator"))).isFalse();
    }

    @Test
    void extractWorkspaceId_ParsesCanonicalUuidAndRejectsMalformedPaths() {
        UUID wsId = UUID.fromString("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11");
        String upper = wsId.toString().toUpperCase(Locale.ROOT);

        assertThat(RequestPaths.extractWorkspaceId("/ws/" + wsId + "/scim/v2")).isEqualTo(wsId);
        assertThat(RequestPaths.extractWorkspaceId("/ws/" + wsId + "/scim/v2/")).isEqualTo(wsId);
        assertThat(RequestPaths.extractWorkspaceId("/ws/" + upper + "/scim/v2/Users")).isEqualTo(wsId);

        assertThat(RequestPaths.extractWorkspaceId(null)).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/actuator/health")).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws/")).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws//scim/v2/Users")).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws/" + wsId)).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws/" + wsId + "/other")).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws/" + wsId + "/other/scim/v2/Users")).isNull();
        assertThat(RequestPaths.extractWorkspaceId("/ws/not-a-uuid/scim/v2/Users")).isNull();
        // Short-form UUIDs without full 36-char representation must be rejected
        assertThat(RequestPaths.extractWorkspaceId("/ws/1-1-1-1-1/scim/v2/Users")).isNull();
        // 36-char non-hex string must be rejected
        assertThat(RequestPaths.extractWorkspaceId("/ws/zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz/scim/v2/Users")).isNull();
    }
}
