package de.palsoftware.scim.server.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

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
    private static final int MAX_STARTUP_ATTEMPTS = 3;

    private static final PostgreSQLContainer<?> POSTGRES;
    private static final String RESOLVED_JDBC_URL;

    static {
        InitializedPostgres initialized = startAndInitializePostgres();
        POSTGRES = initialized.container();
        RESOLVED_JDBC_URL = initialized.jdbcUrl();
    }

    private record InitializedPostgres(PostgreSQLContainer<?> container, String jdbcUrl) {}

    @SuppressWarnings("resource")
    private static InitializedPostgres startAndInitializePostgres() {
        Exception lastFailure = null;
        for (int attempt = 1; attempt <= MAX_STARTUP_ATTEMPTS; attempt++) {
            PostgreSQLContainer<?> candidate = new PostgreSQLContainer<>("postgres:17-alpine3.23")
                    .withDatabaseName("scimplayground")
                    .withUsername("scim_playground")
                    .withPassword("scim_playground")
                    .withNetwork(NETWORK)
                    .withNetworkAliases(DB_REPO_HOST);
            try {
                candidate.start();
                Path localSqlDir = resolveLocalSqlDir();
                boolean migratedByContainer = runDbMigrations(candidate, hasExplicitDbImage(), localSqlDir != null);
                String verifiedJdbcUrl = probeHostJdbcUrl(candidate);
                ensureSchemaUpToDate(verifiedJdbcUrl, candidate.getUsername(), candidate.getPassword(),
                        localSqlDir, migratedByContainer);
                return new InitializedPostgres(candidate, verifiedJdbcUrl);
            } catch (Exception e) {
                lastFailure = e;
                try {
                    candidate.stop();
                } catch (Exception stopEx) {
                    e.addSuppressed(stopEx);
                }
            }
        }
        throw new RuntimeException(
                "Failed to initialize test database schema after " + MAX_STARTUP_ATTEMPTS + " attempts",
                lastFailure);
    }

    @SuppressWarnings("resource")
    private static boolean runDbMigrations(PostgreSQLContainer<?> postgres,
                                           boolean explicitDbImage,
                                           boolean hasLocalSqlFallback) {
        try (GenericContainer<?> migrationContainer = new GenericContainer<>(resolveDbImage())
                .withNetwork(NETWORK)
                .withEnv("FLYWAY_URL", "jdbc:postgresql://" + DB_REPO_HOST + ":5432/" + postgres.getDatabaseName())
                .withEnv("FLYWAY_USER", postgres.getUsername())
                .withEnv("FLYWAY_PASSWORD", postgres.getPassword())
                .withEnv("FLYWAY_DEFAULT_SCHEMA", SCHEMA)
                .withEnv("FLYWAY_SCHEMAS", SCHEMA)
                .withEnv("FLYWAY_CREATE_SCHEMAS", "true")
                .withStartupCheckStrategy(new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))) {
            migrationContainer.start();
            return true;
        } catch (RuntimeException ex) {
            if (!explicitDbImage && hasLocalSqlFallback) {
                return false;
            }
            throw ex;
        }
    }

    private static void ensureSchemaUpToDate(String jdbcUrl,
                                             String username,
                                             String password,
                                             Path localSqlDir,
                                             boolean migratedByContainer) throws SQLException, IOException {
        try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
            boolean hasWorkspaces = tableExists(connection, "workspaces");
            boolean hasAsyncEvents = tableExists(connection, "scim_async_events");
            boolean hasV5Constraints = constraintExists(connection, "chk_scim_users_password_bcrypt");
            if (hasWorkspaces && hasAsyncEvents && hasV5Constraints) {
                return;
            }
            if (localSqlDir == null) {
                if (migratedByContainer && hasWorkspaces && hasAsyncEvents) {
                    return;
                }
                if (!migratedByContainer) {
                    throw new SQLException("No local SQL migration directory found and DB migration image was unavailable");
                }
                throw new SQLException("Test database schema '" + SCHEMA
                        + "' is missing required tables (scim_async_events); rebuild scim-server-db image or provide ../scim-server-db/sql");
            }
            int minVersion = !hasWorkspaces ? 1 : (!hasAsyncEvents ? 2 : 5);
            List<Path> migrationFiles;
            try (Stream<Path> stream = Files.list(localSqlDir)) {
                migrationFiles = stream
                        .filter(Files::isRegularFile)
                        .filter(p -> parseMigrationVersion(p) >= minVersion)
                        .sorted(Comparator.comparingInt(PostgresIntegrationTestSupport::parseMigrationVersion)
                                .thenComparing(p -> p.getFileName().toString()))
                        .toList();
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA);
                statement.execute("SET search_path TO " + SCHEMA);
                for (Path sqlFile : migrationFiles) {
                    String sql = Files.readString(sqlFile, StandardCharsets.UTF_8);
                    if (!sql.isBlank()) {
                        statement.execute(sql);
                    }
                }
            }
        }
    }

    private static boolean tableExists(Connection connection, String tableName) throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT to_regclass('" + SCHEMA + "." + tableName + "')")) {
            return rs.next() && rs.getString(1) != null;
        }
    }

    private static boolean constraintExists(Connection connection, String constraintName) throws SQLException {
        String sql = "SELECT 1 FROM pg_constraint c "
                + "JOIN pg_namespace n ON n.oid = c.connamespace "
                + "WHERE n.nspname = '" + SCHEMA + "' AND c.conname = '" + constraintName + "'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        }
    }

    private static Path resolveLocalSqlDir() {
        for (Path candidate : List.of(Path.of("../scim-server-db/sql"), Path.of("scim-server-db/sql"))) {
            if (Files.isDirectory(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static int parseMigrationVersion(Path path) {
        String name = path.getFileName().toString();
        if (!name.startsWith("V") || !name.endsWith(".sql")) {
            return -1;
        }
        int sep = name.indexOf("__");
        if (sep <= 1) {
            return -1;
        }
        try {
            return Integer.parseInt(name.substring(1, sep));
        } catch (NumberFormatException _) {
            return -1;
        }
    }

    private static boolean hasExplicitDbImage() {
        String prop = System.getProperty(DB_IMAGE_PROPERTY);
        if (prop != null && !prop.isBlank()) {
            return true;
        }
        String env = System.getenv(DB_IMAGE_ENV);
        return env != null && !env.isBlank();
    }

    private static String probeHostJdbcUrl(PostgreSQLContainer<?> postgres) throws SQLException {
        List<String> candidates = buildCandidateJdbcUrls(postgres.getJdbcUrl());
        SQLException lastException = null;
        for (String runtimeUrl : candidates) {
            String probeUrl = runtimeUrl + "&connectTimeout=3&socketTimeout=5&loginTimeout=3";
            try (Connection connection = DriverManager.getConnection(
                    probeUrl, postgres.getUsername(), postgres.getPassword());
                 Statement statement = connection.createStatement()) {
                statement.execute("SELECT 1");
                return runtimeUrl;
            } catch (SQLException ex) {
                if (lastException != null) {
                    ex.addSuppressed(lastException);
                }
                lastException = ex;
            }
        }
        throw lastException != null
                ? lastException
                : new SQLException("No reachable host JDBC URL for Testcontainers PostgreSQL");
    }

    private static List<String> buildCandidateJdbcUrls(String rawJdbcUrl) {
        List<String> urls = new ArrayList<>(5);
        urls.add(rewriteJdbcUrl(rawJdbcUrl, "localhost", true));
        urls.add(rewriteJdbcUrl(rawJdbcUrl, "localhost", false));
        urls.add(rewriteJdbcUrl(rawJdbcUrl, "[::1]", true));
        urls.add(rewriteJdbcUrl(rawJdbcUrl, "127.0.0.1", true));
        urls.add(rewriteJdbcUrl(rawJdbcUrl, "127.0.0.1", false));
        return urls;
    }

    private static String rewriteJdbcUrl(String rawJdbcUrl, String targetHost, boolean disableSsl) {
        final String prefix = "jdbc:postgresql://";
        String rewritten = rawJdbcUrl;
        if (rawJdbcUrl.startsWith(prefix)) {
            String rest = rawJdbcUrl.substring(prefix.length());
            int slashIdx = rest.indexOf('/');
            if (slashIdx > 0) {
                String authority = rest.substring(0, slashIdx);
                int portColonIdx = authority.lastIndexOf(':');
                if (portColonIdx > 0) {
                    String portPart = authority.substring(portColonIdx);
                    String pathAndQuery = rest.substring(slashIdx);
                    rewritten = prefix + targetHost + portPart + pathAndQuery;
                }
            }
        }
        String withSchema = rewritten.contains("?")
                ? rewritten + "&currentSchema=" + SCHEMA
                : rewritten + "?currentSchema=" + SCHEMA;
        return disableSsl ? withSchema + "&sslmode=disable" : withSchema;
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
        registry.add("spring.datasource.url", () -> RESOLVED_JDBC_URL);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.default-schema", () -> SCHEMA);
        registry.add("spring.flyway.schemas", () -> SCHEMA);
        registry.add("spring.flyway.create-schemas", () -> "true");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> SCHEMA);
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.datasource.hikari.minimum-idle", () -> 1);
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 10);
        registry.add("spring.datasource.hikari.connection-timeout", () -> 20000);
    }
}