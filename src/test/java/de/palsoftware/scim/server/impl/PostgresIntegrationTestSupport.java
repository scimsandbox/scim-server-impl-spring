package de.palsoftware.scim.server.impl;

import java.time.Duration;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.utility.DockerImageName;

public abstract class PostgresIntegrationTestSupport {

    private static final String SCHEMA = "scim_api_test";
    private static final String DB_IMAGE_ENV = "SCIM_DB_IMAGE";
    private static final String DB_IMAGE_PROPERTY = "scim.db.image";
    private static final String DEFAULT_DB_IMAGE = "scim-server-db:latest";
    private static final String DB_REPO_HOST = "scim-db";
    private static final Network NETWORK = Network.newNetwork();

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine3.23")
            .withDatabaseName("scimplayground")
            .withUsername("scim_playground")
            .withPassword("scim_playground")
            .withNetwork(NETWORK)
            .withNetworkAliases(DB_REPO_HOST);

    static {
        POSTGRES.start();
        try {
            runDbMigrations();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize test database schema", e);
        }
    }

    @SuppressWarnings("resource")
    private static void runDbMigrations() {
        try (GenericContainer<?> migrationContainer = new GenericContainer<>(resolveDbImage())
                .withNetwork(NETWORK)
                .withEnv("FLYWAY_URL", "jdbc:postgresql://" + DB_REPO_HOST + ":5432/" + POSTGRES.getDatabaseName())
                .withEnv("FLYWAY_USER", POSTGRES.getUsername())
                .withEnv("FLYWAY_PASSWORD", POSTGRES.getPassword())
                .withEnv("FLYWAY_DEFAULT_SCHEMA", SCHEMA)
                .withEnv("FLYWAY_SCHEMAS", SCHEMA)
                .withEnv("FLYWAY_CREATE_SCHEMAS", "true")
                .withStartupCheckStrategy(new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))) {
            migrationContainer.start();
        }
    }

    private static DockerImageName resolveDbImage() {
        String configuredImage = System.getProperty(DB_IMAGE_PROPERTY);
        if (configuredImage == null || configuredImage.isBlank()) {
            configuredImage = System.getenv(DB_IMAGE_ENV);
        }
        if (configuredImage == null || configuredImage.isBlank()) {
            configuredImage = DEFAULT_DB_IMAGE;
        }
        return DockerImageName.parse(configuredImage);
    }

    @DynamicPropertySource
    static void registerPostgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.default-schema", () -> SCHEMA);
        registry.add("spring.flyway.schemas", () -> SCHEMA);
        registry.add("spring.flyway.create-schemas", () -> "true");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> SCHEMA);
    }
}