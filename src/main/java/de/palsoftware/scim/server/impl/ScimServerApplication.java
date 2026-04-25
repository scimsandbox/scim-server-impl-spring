package de.palsoftware.scim.server.impl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.cache.annotation.EnableCaching;

import java.time.Clock;

@SpringBootApplication(scanBasePackages = {"de.palsoftware.scim.server.impl",
                                           "de.palsoftware.scim.server.impl.repository"},
                       exclude = UserDetailsServiceAutoConfiguration.class)
@EntityScan(basePackages = {"de.palsoftware.scim.server.impl.model",
                            "de.palsoftware.scim.server.impl"})
@EnableJpaRepositories(basePackages = {"de.palsoftware.scim.server.impl.repository"})
@EnableAsync
@EnableScheduling
@EnableCaching
public class ScimServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScimServerApplication.class, args);
    }

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    public Clock clock() {
        return Clock.systemUTC();
    }
}
