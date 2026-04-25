# SCIM Sandbox - Server Impl Spring

> [!WARNING]
> **Data Privacy / PII**: This application is built as a sandbox. It intentionally stores all SCIM request and response payloads in the database without redaction for debugging purposes. See [SECURITY.md](SECURITY.md) before deploying outside of a local environment.

This repository contains the standalone Spring Boot SCIM 2.0 service
implementation for the SCIM Sandbox project. It provides the server-side
SCIM API, workspace-scoped bearer-token auth, request logging, cleanup
jobs, and actuator endpoints.

## What Is In This Repo

- `src/main/java/de/palsoftware/scim/server/impl/ScimServerApplication.java` boots the service and scans the API, persistence, security, and SCIM support packages.
- `src/main/java/de/palsoftware/scim/server/impl/controller` contains the SCIM `Users`, `Groups`, `Bulk`, discovery, and `/Me` controllers.
- `src/main/java/de/palsoftware/scim/server/impl/service`, `model`, and `repository` contain the domain, persistence, and business logic.
- `src/main/java/de/palsoftware/scim/server/impl/scim` contains SCIM schema, filter, mapping, patch, compatibility, and error-handling logic.
- `src/main/resources/application.yml` defines the default runtime settings and environment-variable bindings.
- `src/test/java/de/palsoftware/scim/server/impl` contains unit and integration tests, including the Testcontainers-backed PostgreSQL bootstrap.
- `Dockerfile` packages the service as a container image.

## API Shape

The SCIM API is workspace-scoped and uses UUID workspace IDs:

```text
/ws/{workspaceId}/scim/v2/**
```

An optional compatibility segment is also supported:

```text
/ws/{workspaceId}/scim/v2/{compat}/**
```

Requests use bearer-token authentication:

```text
Authorization: Bearer <workspace-token>
```

The service also exposes `/actuator/health` and `/actuator/prometheus`,
which are not authenticated.

## Running the Service

Prerequisites:

- JDK 25
- Maven 3.9+
- Docker if you want to run the integration suite or build the image
- PostgreSQL if you want to point the app at a local database

Set the minimum runtime variables:

```bash
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/scimplayground
export SPRING_DATASOURCE_USERNAME=postgres
export SPRING_DATASOURCE_PASSWORD=postgres
```

Start the service from the repository root:

```bash
mvn spring-boot:run
```

The application listens on port `8080` by default.

## Example Calls

Discovery:

```bash
export WORKSPACE_ID=<workspace-uuid>
export TOKEN=<workspace-token>

curl \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/scim+json" \
  http://localhost:8080/ws/${WORKSPACE_ID}/scim/v2/ServiceProviderConfig
```

Create a user:

```bash
curl \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/scim+json" \
  -H "Accept: application/scim+json" \
  http://localhost:8080/ws/${WORKSPACE_ID}/scim/v2/Users \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com",
    "name": {
      "givenName": "Alice",
      "familyName": "Example"
    },
    "active": true
  }'
```

Actuator health:

```bash
curl http://localhost:8080/actuator/health
```

## Configuration

The default application settings live in
`src/main/resources/application.yml`.

Required at runtime:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`

Useful optional settings:

- `app.cleanup.workspace.enabled`
- `app.cleanup.workspace.cron`
- `app.cleanup.workspace.zone`
- `app.cleanup.workspace.stale-after`

Workspace cleanup is enabled by default and removes stale workspaces on a
schedule. The default retention window is `P3M`.

The application enforces a strict 1MB limit on request payloads to prevent
exhaustion attacks (particularly relevant for the SCIM Bulk endpoint). This
can be overridden by tuning `server.tomcat.max-http-form-post-size` and
`spring.servlet.multipart.*` properties.

### Token Expiration

Workspace bearer tokens carry an optional `expires_at` timestamp. The
`BearerTokenAuthFilter` checks this field on every request and rejects
expired tokens with a `401 Unauthorized` response containing the detail
`"Token has expired"`. Legacy tokens with a `NULL` `expires_at` are treated
as non-expiring and continue to be accepted.

New tokens created through the management UI (`scim-server-ui-spring`)
default to a 30-day validity (`P30D`), configurable via the
`APP_TOKEN_DEFAULT_VALIDITY` environment variable.

### Token Caching

Token lookups are cached with Caffeine (`expireAfterWrite=60s,
maximumSize=10000`). Because the expiration check compares the cached
entity's `expiresAt` field against the current time on every request, an
expired token is correctly rejected even while it remains in the cache.
The 60-second cache TTL means that a revoked (but not expired) token may
continue to authenticate for up to 60 seconds after revocation.

## Testing

Run the full validation suite from the repository root:

```bash
mvn clean verify
```

The integration tests use Testcontainers, so Docker must be available.
The PostgreSQL bootstrap expects a migration image named
`scim-server-db:latest` by default. If you need to build that image first,
or use a different tag, either build the sibling module image locally or
set `SCIM_DB_IMAGE` or `-Dscim.db.image=...` before running the suite.

## Versioning

The working version lives in `pom.xml`. The manual release workflow runs
from `main`, reads the current version from `pom.xml`, strips
`-SNAPSHOT` when present, tags the release as `vX.Y.Z`, packages a source
bundle and JAR, and creates a GitHub release.

Publishing that GitHub release triggers the Docker publish workflow, which
builds and pushes `edipal/scim-server-impl-spring` with `latest`,
`vX.Y.Z`, `X.Y.Z`, and `X.Y` tags.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md).
