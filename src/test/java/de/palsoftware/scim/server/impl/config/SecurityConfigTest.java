package de.palsoftware.scim.server.impl.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.server.impl.filter.PayloadSizeLimitFilter;
import de.palsoftware.scim.server.impl.filter.ServletPayloadStreamGuardFilter;
import de.palsoftware.scim.server.impl.filter.ThrottlingFilter;
import de.palsoftware.scim.server.impl.filter.WorkspaceRateLimitFilter;
import de.palsoftware.scim.server.impl.logging.RequestResponseLoggingFilter;
import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsFilter;
import de.palsoftware.scim.server.impl.model.ScimRequestLog;
import de.palsoftware.scim.server.impl.model.Workspace;
import de.palsoftware.scim.server.impl.model.WorkspaceToken;
import de.palsoftware.scim.server.impl.repository.ScimRequestLogRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceRepository;
import de.palsoftware.scim.server.impl.repository.WorkspaceTokenRepository;
import de.palsoftware.scim.server.impl.security.ActuatorApiKeyAuthFilter;
import de.palsoftware.scim.server.impl.security.BearerTokenAuthFilter;
import de.palsoftware.scim.server.impl.security.TokenSecurityUtil;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.boot.web.server.WebServer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.filter.FormContentFilter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecurityConfigTest {

    @Configuration(proxyBeanMethods = false)
    static class TestSupportBeans {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        WorkspaceTokenRepository workspaceTokenRepository() {
            return Mockito.mock(WorkspaceTokenRepository.class);
        }

        @Bean
        WorkspaceRepository workspaceRepository() {
            return Mockito.mock(WorkspaceRepository.class);
        }

        @Bean
        ScimRequestLogRepository scimRequestLogRepository() {
            return Mockito.mock(ScimRequestLogRepository.class);
        }
    }

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withInitializer(ctx -> ctx.getBeanFactory()
                    .setConversionService(new ApplicationConversionService()))
            .withConfiguration(AutoConfigurations.of(
                    WebMvcAutoConfiguration.class,
                    SecurityAutoConfiguration.class))
            .withUserConfiguration(
                    TestSupportBeans.class,
                    ServletPayloadStreamGuardFilter.class,
                    ScimOperationMetricsFilter.class,
                    ThrottlingFilter.class,
                    WorkspaceRateLimitFilter.class,
                    RequestResponseLoggingFilter.class,
                    PayloadSizeLimitFilter.class,
                    SecurityConfig.class);

    @Test
    void securityFilterChain_WhenRateLimitEnabled_OrdersThreeTierFiltersAndLoggingBeforePayloadLimit() {
        contextRunner
                .withPropertyValues(
                        "spring.mvc.formcontent.filter.enabled=false",
                        "app.rate-limit.enabled=true",
                        "app.rate-limit.requests-per-second=200",
                        "app.rate-limit.wait-timeout=0s",
                        "app.security.actuator.api-key=unit-test-key")
                .run(context -> {
                    assertThat(context.getBeansOfType(ThrottlingFilter.class)).hasSize(1);
                    assertThat(context.getBeansOfType(WorkspaceRateLimitFilter.class)).hasSize(1);
                    assertThat(context.getBeansOfType(ServletPayloadStreamGuardFilter.class)).hasSize(1);
                    assertThat(context.getBeansOfType(FormContentFilter.class)).isEmpty();
                    assertThat(context.getBeansOfType(FilterRegistrationBean.class)).isEmpty();

                    SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
                    List<Class<?>> filterTypes = chain.getFilters().stream()
                            .<Class<?>>map(Filter::getClass)
                            .toList();

                    int metricsIdx = filterTypes.indexOf(ScimOperationMetricsFilter.class);
                    int actuatorIdx = filterTypes.indexOf(ActuatorApiKeyAuthFilter.class);
                    int throttlingIdx = filterTypes.indexOf(ThrottlingFilter.class);
                    int bearerIdx = filterTypes.indexOf(BearerTokenAuthFilter.class);
                    int workspaceRateIdx = filterTypes.indexOf(WorkspaceRateLimitFilter.class);
                    int loggingIdx = filterTypes.indexOf(RequestResponseLoggingFilter.class);
                    int payloadIdx = filterTypes.indexOf(PayloadSizeLimitFilter.class);

                    assertThat(metricsIdx).isGreaterThanOrEqualTo(0);
                    assertThat(actuatorIdx).isGreaterThan(metricsIdx);
                    assertThat(throttlingIdx).isGreaterThan(actuatorIdx);
                    assertThat(bearerIdx).isGreaterThan(throttlingIdx);
                    assertThat(workspaceRateIdx).isGreaterThan(bearerIdx);
                    assertThat(loggingIdx).isGreaterThan(workspaceRateIdx);
                    assertThat(payloadIdx).isGreaterThan(loggingIdx);

                    // Verify request matchers (scimPaths, actuatorPaths, errorPaths, denyAll)
                    ServletPayloadStreamGuardFilter streamGuard = context.getBean(ServletPayloadStreamGuardFilter.class);
                    Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
                    MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context)
                            .addFilters(streamGuard, springSecurityFilterChain)
                            .build();

                    mockMvc.perform(post("/ws/" + UUID.randomUUID() + "/scim/v2/Users")
                                    .contentType("application/scim+json")
                                    .content("{}"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(get("/actuator"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(get("/actuator")
                                    .header("X-API-Key", "unit-test-key"))
                            .andExpect(status().isNotFound());

                    mockMvc.perform(get("/actuator/prometheus"))
                            .andExpect(status().isUnauthorized());

                    mockMvc.perform(post("/error"))
                            .andExpect(status().isNotFound());

                    mockMvc.perform(get("/completely-unmapped"))
                            .andExpect(status().isForbidden());
                });
    }

    @Test
    void securityFilterChain_WhenRateLimitDisabled_OmitsRateLimitFiltersAndUpdatesRuntimePort() {
        contextRunner
                .withPropertyValues("app.rate-limit.enabled=false")
                .run(context -> {
                    assertThat(context.getBeansOfType(ThrottlingFilter.class)).isEmpty();
                    assertThat(context.getBeansOfType(WorkspaceRateLimitFilter.class)).isEmpty();

                    SecurityFilterChain chain = context.getBean(SecurityFilterChain.class);
                    List<Class<?>> filterTypes = chain.getFilters().stream()
                            .<Class<?>>map(Filter::getClass)
                            .toList();

                    assertThat(filterTypes)
                            .doesNotContain(ThrottlingFilter.class, WorkspaceRateLimitFilter.class);

                    int metricsIdx = filterTypes.indexOf(ScimOperationMetricsFilter.class);
                    int actuatorIdx = filterTypes.indexOf(ActuatorApiKeyAuthFilter.class);
                    int bearerIdx = filterTypes.indexOf(BearerTokenAuthFilter.class);
                    int loggingIdx = filterTypes.indexOf(RequestResponseLoggingFilter.class);
                    int payloadIdx = filterTypes.indexOf(PayloadSizeLimitFilter.class);

                    assertThat(actuatorIdx).isGreaterThan(metricsIdx);
                    assertThat(bearerIdx).isGreaterThan(actuatorIdx);
                    assertThat(loggingIdx).isGreaterThan(bearerIdx);
                    assertThat(payloadIdx).isGreaterThan(loggingIdx);

                    // Verify WebServerInitializedEvent listener forwards runtime ports cleanly
                    SecurityConfig securityConfig = context.getBean(SecurityConfig.class);
                    WebServer webServer = Mockito.mock(WebServer.class);
                    when(webServer.getPort()).thenReturn(19090);
                    WebServerApplicationContext wsContext = Mockito.mock(WebServerApplicationContext.class);
                    when(wsContext.getServerNamespace()).thenReturn("management");
                    WebServerInitializedEvent event = Mockito.mock(WebServerInitializedEvent.class);
                    when(event.getWebServer()).thenReturn(webServer);
                    when(event.getApplicationContext()).thenReturn(wsContext);

                    securityConfig.onWebServerInitialized(event);
                });
    }

    @Test
    void securityFilterChain_UnauthenticatedLookupLimiterHonorsDefaultPropertiesAndCustomBeanOverride() {
        UUID wsId = UUID.randomUUID();
        String usersPath = "/ws/" + wsId + "/scim/v2/Users";

        // (a) Default SecurityConfig property wiring: unauthenticated-burst=2, unauthenticated-requests-per-second=0.5
        contextRunner
                .withPropertyValues(
                        "spring.mvc.formcontent.filter.enabled=false",
                        "app.rate-limit.enabled=true",
                        "app.rate-limit.requests-per-second=200",
                        "app.rate-limit.unauthenticated-requests-per-second=0.5",
                        "app.rate-limit.unauthenticated-burst=2",
                        "app.rate-limit.wait-timeout=0s")
                .run(context -> {
                    WorkspaceTokenRepository tokenRepo = context.getBean(WorkspaceTokenRepository.class);
                    when(tokenRepo.findByTokenHashAndNotRevoked(any())).thenReturn(Optional.empty());

                    ServletPayloadStreamGuardFilter streamGuard = context.getBean(ServletPayloadStreamGuardFilter.class);
                    Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
                    MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context)
                            .addFilters(streamGuard, springSecurityFilterChain)
                            .build();

                    for (int idx = 1; idx <= 2; idx++) {
                        final String remoteIp = "198.51.100." + idx;
                        mockMvc.perform(get(usersPath)
                                        .with(req -> {
                                            req.setRemoteAddr(remoteIp);
                                            return req;
                                        })
                                        .header("Authorization", "Bearer bad-" + idx))
                                .andExpect(status().isUnauthorized());
                    }
                    verify(tokenRepo, times(2)).findByTokenHashAndNotRevoked(any());

                    mockMvc.perform(get(usersPath)
                                    .with(req -> {
                                        req.setRemoteAddr("198.51.100.3");
                                        return req;
                                    })
                                    .header("Authorization", "Bearer bad-3"))
                            .andExpect(status().isTooManyRequests())
                            .andExpect(header().string("Retry-After", "2"));
                    verify(tokenRepo, times(2)).findByTokenHashAndNotRevoked(any());
                });

        // (b) Custom UnauthenticatedLookupLimiter @Bean registered in context is honored via ObjectProvider
        AtomicInteger customAcquisitions = new AtomicInteger();
        ThrottlingFilter.UnauthenticatedLookupLimiter customLimiter =
                new ThrottlingFilter.UnauthenticatedLookupLimiter() {
                    @Override
                    public boolean isKnownActiveToken(String tokenCacheKey) {
                        return false;
                    }

                    @Override
                    public ThrottlingFilter.AcquireResult tryAcquireLookupPermit() {
                        customAcquisitions.incrementAndGet();
                        return ThrottlingFilter.AcquireResult.rejected(7L);
                    }

                    @Override
                    public void onValidTokenLookup(String tokenCacheKey, boolean refundLookupPermit) {
                        // Not reached when rejected
                    }

                    @Override
                    public void evictToken(String tokenCacheKey) {
                        // Not reached when rejected
                    }
                };

        contextRunner
                .withBean(ThrottlingFilter.UnauthenticatedLookupLimiter.class, () -> customLimiter)
                .withPropertyValues(
                        "spring.mvc.formcontent.filter.enabled=false",
                        "app.rate-limit.enabled=true",
                        "app.rate-limit.requests-per-second=200",
                        "app.rate-limit.wait-timeout=0s")
                .run(context -> {
                    WorkspaceTokenRepository tokenRepo = context.getBean(WorkspaceTokenRepository.class);
                    ServletPayloadStreamGuardFilter streamGuard = context.getBean(ServletPayloadStreamGuardFilter.class);
                    Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
                    MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context)
                            .addFilters(streamGuard, springSecurityFilterChain)
                            .build();

                    mockMvc.perform(get(usersPath)
                                    .with(req -> {
                                        req.setRemoteAddr("198.51.100.9");
                                        return req;
                                    })
                                    .header("Authorization", "Bearer bad-custom"))
                            .andExpect(status().isTooManyRequests())
                            .andExpect(header().string("Retry-After", "7"));

                    assertThat(customAcquisitions.get()).isEqualTo(1);
                    verify(tokenRepo, never()).findByTokenHashAndNotRevoked(any());
                });
    }

    @Test
    void fullPipeline_UnauthenticatedFormUrlEncodedPutSkipsStreamAndAuthenticatedOversizedBulkLogs413() {
        contextRunner
                .withPropertyValues(
                        "spring.mvc.formcontent.filter.enabled=false",
                        "app.rate-limit.enabled=true",
                        "app.rate-limit.requests-per-second=200",
                        "app.rate-limit.wait-timeout=0s")
                .run(context -> {
                    ServletPayloadStreamGuardFilter streamGuard = context.getBean(ServletPayloadStreamGuardFilter.class);
                    Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
                    WorkspaceTokenRepository tokenRepo = context.getBean(WorkspaceTokenRepository.class);
                    WorkspaceRepository workspaceRepo = context.getBean(WorkspaceRepository.class);
                    ScimRequestLogRepository logRepo = context.getBean(ScimRequestLogRepository.class);

                    UUID wsId = UUID.randomUUID();
                    Workspace ws = new Workspace();
                    ws.setId(wsId);
                    ws.setCreatedByUsername("admin");
                    when(workspaceRepo.getReferenceById(wsId)).thenReturn(ws);
                    when(logRepo.save(any(ScimRequestLog.class))).thenAnswer(inv -> inv.getArgument(0));

                    // 1. Unauthenticated chunked PUT with application/x-www-form-urlencoded > 1 MiB:
                    //    0 bytes read from underlying stream and 401 returned with 0 request log entries!
                    AtomicInteger unauthBytesRead = new AtomicInteger();
                    HttpServletRequest unauthChunkedPut = streamingRequest(
                            "PUT",
                            "/ws/" + wsId + "/scim/v2/Users/" + UUID.randomUUID(),
                            "application/x-www-form-urlencoded",
                            null,
                            PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES * 3,
                            unauthBytesRead);
                    MockHttpServletResponse unauthResp = new MockHttpServletResponse();
                    streamGuard.doFilter(unauthChunkedPut, unauthResp,
                            (req, res) -> springSecurityFilterChain.doFilter(req, res, (_, _) -> {}));

                    assertThat(unauthResp.getStatus()).isEqualTo(401);
                    assertThat(unauthBytesRead.get()).isZero();
                    verify(logRepo, never()).save(any());

                    // 2. Configure valid token for Workspace
                    String rawToken = "valid-bulk-token";
                    WorkspaceToken wsToken = new WorkspaceToken();
                    wsToken.setWorkspace(ws);
                    wsToken.setTokenHash(TokenSecurityUtil.sha256Hex(rawToken));
                    wsToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));
                    when(tokenRepo.findByTokenHashAndNotRevoked(wsToken.getTokenHash())).thenReturn(Optional.of(wsToken));

                    // 2a. Authenticated Bulk POST with Content-Length > 1 MiB -> 413 AND logged in scim_request_logs
                    MockHttpServletRequest fixedBulkReq = new MockHttpServletRequest(
                            "POST", "/ws/" + wsId + "/scim/v2/Bulk") {
                        @Override
                        public long getContentLengthLong() {
                            return PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1024L;
                        }

                        @Override
                        public int getContentLength() {
                            return PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 1024;
                        }
                    };
                    fixedBulkReq.setContentType("application/scim+json");
                    fixedBulkReq.addHeader("Authorization", "Bearer " + rawToken);
                    fixedBulkReq.setContent("{}".getBytes(StandardCharsets.UTF_8));
                    MockHttpServletResponse fixedBulkResp = new MockHttpServletResponse();

                    streamGuard.doFilter(fixedBulkReq, fixedBulkResp,
                            (req, res) -> springSecurityFilterChain.doFilter(req, res, (_, _) -> {}));

                    assertThat(fixedBulkResp.getStatus()).isEqualTo(413);
                    assertThat(fixedBulkResp.getContentAsString())
                            .contains("\"status\":\"413\"")
                            .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");

                    // 2b. Authenticated Bulk POST with chunked stream > 1 MiB -> 413 AND logged in scim_request_logs
                    AtomicInteger authChunkedBytesRead = new AtomicInteger();
                    HttpServletRequest chunkedBulkReq = streamingRequest(
                            "POST",
                            "/ws/" + wsId + "/scim/v2/Bulk",
                            "application/scim+json",
                            "Bearer " + rawToken,
                            PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES * 2,
                            authChunkedBytesRead);
                    MockHttpServletResponse chunkedBulkResp = new MockHttpServletResponse();

                    streamGuard.doFilter(chunkedBulkReq, chunkedBulkResp,
                            (req, res) -> springSecurityFilterChain.doFilter(
                                    req, res, (downstreamReq, _) -> downstreamReq.getInputStream().readAllBytes()));

                    assertThat(chunkedBulkResp.getStatus()).isEqualTo(413);
                    assertThat(chunkedBulkResp.getContentAsString())
                            .contains("\"status\":\"413\"")
                            .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");
                    assertThat(authChunkedBytesRead.get())
                            .isLessThanOrEqualTo(PayloadSizeLimitFilter.MAX_PAYLOAD_BYTES + 8192);

                    ArgumentCaptor<ScimRequestLog> logCaptor = ArgumentCaptor.forClass(ScimRequestLog.class);
                    verify(logRepo, times(2)).save(logCaptor.capture());
                    List<ScimRequestLog> savedLogs = logCaptor.getAllValues();
                    assertThat(savedLogs).hasSize(2);
                    for (ScimRequestLog saved : savedLogs) {
                        assertThat(saved.getStatus()).isEqualTo(413);
                        assertThat(saved.getPath()).isEqualTo("/ws/" + wsId + "/scim/v2/Bulk");
                        assertThat(saved.getResponseBody())
                                .contains("\"status\":\"413\"")
                                .contains("Bulk request payload size exceeds maxPayloadSize of 1048576 bytes");
                    }
                });
    }

    private static HttpServletRequest streamingRequest(String method,
                                                       String uri,
                                                       String contentType,
                                                       String authHeader,
                                                       int totalStreamBytes,
                                                       AtomicInteger bytesReadCounter) {
        MockHttpServletRequest base = new MockHttpServletRequest(method, uri);
        base.setContentType(contentType);
        base.addHeader("Transfer-Encoding", "chunked");
        if (authHeader != null) {
            base.addHeader("Authorization", authHeader);
        }
        return new HttpServletRequestWrapper(base) {
            @Override
            public int getContentLength() {
                return -1;
            }

            @Override
            public long getContentLengthLong() {
                return -1L;
            }

            @Override
            public ServletInputStream getInputStream() {
                return new ServletInputStream() {
                    private int pos = 0;

                    @Override
                    public boolean isFinished() {
                        return pos >= totalStreamBytes;
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                    }

                    @Override
                    public int read() {
                        if (pos >= totalStreamBytes) {
                            return -1;
                        }
                        pos++;
                        bytesReadCounter.incrementAndGet();
                        return 'a';
                    }

                    @Override
                    public int read(byte[] b, int off, int len) {
                        if (pos >= totalStreamBytes) {
                            return -1;
                        }
                        int n = Math.min(len, Math.min(4096, totalStreamBytes - pos));
                        Arrays.fill(b, off, off + n, (byte) 'a');
                        pos += n;
                        bytesReadCounter.addAndGet(n);
                        return n;
                    }
                };
            }
        };
    }
}
