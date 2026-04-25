package de.palsoftware.scim.server.impl.logging;

import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RequestResponseLoggingFilterTest {

    private ScimRequestLogRepository logRepository;
    private WorkspaceRepository workspaceRepository;
    private RequestResponseLoggingFilter filter;
    private UUID workspaceId;

    @BeforeEach
    void setUp() {
        logRepository = Mockito.mock(ScimRequestLogRepository.class);
        workspaceRepository = Mockito.mock(WorkspaceRepository.class);
        filter = new RequestResponseLoggingFilter(logRepository, workspaceRepository);
        workspaceId = UUID.randomUUID();

        Workspace workspace = new Workspace();
        workspace.setId(workspaceId);

        when(workspaceRepository.getReferenceById(workspaceId)).thenReturn(workspace);
        when(logRepository.save(any(ScimRequestLog.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void requestAndResponseBodies_AreStoredWithoutRedaction() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/ws/" + workspaceId + "/scim/v2/Users");
        request.setCharacterEncoding(StandardCharsets.UTF_8.name());
        request.setContentType("application/scim+json");
        request.setContent(("{\"userName\":\"alice\",\"password\":\"s\\\"ecret\","
                + "\"nested\":{\"password\":\"another-secret\"}}")
                .getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = (servletRequest, servletResponse) -> {
            servletRequest.getInputStream().readAllBytes();
            HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
            httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
            httpServletResponse.setStatus(HttpServletResponse.SC_CREATED);
            httpServletResponse.getWriter().write("{\"password\":\"reply-secret\",\"detail\":\"created\"}");
        };

        filter.doFilter(request, response, chain);

        ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
        verify(logRepository).save(logCaptor.capture());

        ScimRequestLog savedLog = logCaptor.getValue();
        assertEquals("{\"userName\":\"alice\",\"password\":\"s\\\"ecret\",\"nested\":{\"password\":\"another-secret\"}}",
            savedLog.getRequestBody());
        assertEquals("{\"password\":\"reply-secret\",\"detail\":\"created\"}", savedLog.getResponseBody());
        assertEquals(HttpServletResponse.SC_CREATED, savedLog.getStatus());
        assertEquals("{\"password\":\"reply-secret\",\"detail\":\"created\"}", response.getContentAsString());
    }
}
