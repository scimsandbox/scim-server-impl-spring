package de.palsoftware.scim.server.impl.scim.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScimListResponseTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testIndexPaginationSerialization() throws Exception {
        List<String> items = List.of("item1", "item2");
        ScimListResponse<String> response = ScimListResponse.ofIndex(items, 10, 1);

        Map<String, Object> map = response.toMap();
        assertEquals(10L, map.get("totalResults"));
        assertEquals(1, map.get("startIndex"));
        assertEquals(2, map.get("itemsPerPage"));
        assertFalse(map.containsKey("nextCursor"));
        assertFalse(map.containsKey("previousCursor"));
        assertEquals(items, map.get("Resources"));

        String json = mapper.writeValueAsString(response);
        assertTrue(json.contains("\"startIndex\":1"));
        assertFalse(json.contains("nextCursor"));
        assertFalse(json.contains("previousCursor"));
    }

    @Test
    void testCursorInitialPageSerialization() throws Exception {
        List<String> items = List.of("item1");
        ScimListResponse<String> response = ScimListResponse.ofCursor(items, 10, "scim_cur_next", null);

        Map<String, Object> map = response.toMap();
        assertEquals(10L, map.get("totalResults"));
        assertFalse(map.containsKey("startIndex"));
        assertEquals(1, map.get("itemsPerPage"));
        assertEquals("scim_cur_next", map.get("nextCursor"));
        assertFalse(map.containsKey("previousCursor"));

        String json = mapper.writeValueAsString(response);
        assertFalse(json.contains("startIndex"));
        assertTrue(json.contains("\"nextCursor\":\"scim_cur_next\""));
        assertFalse(json.contains("previousCursor"));
    }

    @Test
    void testCursorMiddlePageSerialization() throws Exception {
        List<String> items = List.of("item2");
        ScimListResponse<String> response = ScimListResponse.ofCursor(items, 10, "scim_cur_next", "scim_cur_prev");

        Map<String, Object> map = response.toMap();
        assertEquals(10L, map.get("totalResults"));
        assertFalse(map.containsKey("startIndex"));
        assertEquals("scim_cur_next", map.get("nextCursor"));
        assertEquals("scim_cur_prev", map.get("previousCursor"));

        String json = mapper.writeValueAsString(response);
        assertFalse(json.contains("startIndex"));
        assertTrue(json.contains("\"nextCursor\":\"scim_cur_next\""));
        assertTrue(json.contains("\"previousCursor\":\"scim_cur_prev\""));
    }

    @Test
    void testCursorFinalPageSerialization() throws Exception {
        List<String> items = List.of("item10");
        ScimListResponse<String> response = ScimListResponse.ofCursor(items, 10, null, "scim_cur_prev");

        Map<String, Object> map = response.toMap();
        assertEquals(10L, map.get("totalResults"));
        assertFalse(map.containsKey("startIndex"));
        assertFalse(map.containsKey("nextCursor"));
        assertEquals("scim_cur_prev", map.get("previousCursor"));

        String json = mapper.writeValueAsString(response);
        assertFalse(json.contains("startIndex"));
        assertFalse(json.contains("nextCursor"));
        assertTrue(json.contains("\"previousCursor\":\"scim_cur_prev\""));
    }
}
