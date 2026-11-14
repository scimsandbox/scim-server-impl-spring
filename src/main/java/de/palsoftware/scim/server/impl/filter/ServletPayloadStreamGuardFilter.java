package de.palsoftware.scim.server.impl.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.scim.error.ScimException;
import de.palsoftware.scim.server.impl.scim.error.ScimFilterErrorWriter;
import de.palsoftware.scim.server.impl.security.RequestPaths;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

/**
 * Outermost servlet-level defense-in-depth guard ({@link Ordered#HIGHEST_PRECEDENCE})
 * wrapping SCIM requests in {@link PayloadSizeLimitFilter.BoundedPayloadRequestWrapper}
 * so that if any pre-authentication servlet filter ever accesses {@code getInputStream()}
 * or {@code getReader()}, reads are strictly bounded at 1 MiB.
 * <p>
 * When nothing reads the request stream prior to authentication, 0 bytes are read here and
 * unauthenticated requests continue to receive {@code 401}/{@code 429} from the security chain.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ServletPayloadStreamGuardFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;

    @Autowired
    public ServletPayloadStreamGuardFilter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public ServletPayloadStreamGuardFilter() {
        this(new ObjectMapper());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !RequestPaths.isScimPath(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest guardedRequest = PayloadSizeLimitFilter.BoundedPayloadRequestWrapper.isBounded(request)
                ? request
                : new PayloadSizeLimitFilter.BoundedPayloadRequestWrapper(
                        request,
                        PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES,
                        PayloadSizeLimitFilter.resolvePayloadLimitDetail(request));
        try {
            filterChain.doFilter(guardedRequest, response);
        } catch (ServletException | IOException | RuntimeException ex) {
            ScimException payloadEx = ScimFilterErrorWriter.findScimException(
                    ex, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            if (payloadEx != null && !response.isCommitted()) {
                response.resetBuffer();
                ScimFilterErrorWriter.writeScimError(
                        response,
                        objectMapper,
                        HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        payloadEx.getScimType(),
                        payloadEx.getMessage());
                return;
            }
            throw ex;
        }
    }
}
