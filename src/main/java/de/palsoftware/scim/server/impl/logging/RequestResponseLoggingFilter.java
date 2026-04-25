package de.palsoftware.scim.server.impl.logging;

import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final Pattern WORKSPACE_PATH = Pattern.compile("/ws/([0-9a-fA-F-]+)/scim/v2/.*");
    private static final int MAX_BODY_CHARS = 20000;

    private final ScimRequestLogRepository logRepository;
    private final WorkspaceRepository workspaceRepository;

    public RequestResponseLoggingFilter(ScimRequestLogRepository logRepository,
            WorkspaceRepository workspaceRepository) {
        this.logRepository = logRepository;
        this.workspaceRepository = workspaceRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/ws/") || !path.contains("/scim/v2/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request, MAX_BODY_CHARS);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            try {
                saveLog(requestWrapper, responseWrapper);
            } finally {
                responseWrapper.copyBodyToResponse();
            }
        }
    }

    private void saveLog(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
        UUID workspaceId = extractWorkspaceId(request.getRequestURI());
        if (workspaceId == null) {
            return;
        }

        ScimRequestLog log = new ScimRequestLog();
        log.setWorkspace(workspaceRepository.getReferenceById(workspaceId));
        log.setMethod(request.getMethod());
        log.setPath(request.getRequestURI());
        log.setStatus(response.getStatus());
        log.setRequestBody(truncate(readBody(request.getContentAsByteArray(), request.getCharacterEncoding())));
        log.setResponseBody(truncate(readBody(response.getContentAsByteArray(), response.getCharacterEncoding())));
        logRepository.save(log);
    }

    private UUID extractWorkspaceId(String path) {
        Matcher matcher = WORKSPACE_PATH.matcher(path);
        if (!matcher.matches()) {
            return null;
        }
        String workspaceId = matcher.group(1);
        try {
            return UUID.fromString(workspaceId);
        } catch (IllegalArgumentException _) {
            return null;
        }
    }

    private String readBody(byte[] body, String encoding) {
        if (body == null || body.length == 0) {
            return null;
        }
        Charset charset = StringUtils.hasText(encoding) ? Charset.forName(encoding) : StandardCharsets.UTF_8;
        return new String(body, charset);
    }

    private String truncate(String body) {
        if (body == null) {
            return null;
        }
        if (body.length() <= MAX_BODY_CHARS) {
            return body;
        }
        return body.substring(0, MAX_BODY_CHARS) + "...";
    }
}
