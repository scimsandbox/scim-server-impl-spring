package de.palsoftware.scim.server.impl.config;

import de.palsoftware.scim.server.impl.metrics.ScimOperationMetricsInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final ScimOperationMetricsInterceptor scimOperationMetricsInterceptor;

    public WebMvcConfig(ScimOperationMetricsInterceptor scimOperationMetricsInterceptor) {
        this.scimOperationMetricsInterceptor = scimOperationMetricsInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(scimOperationMetricsInterceptor);
    }
}