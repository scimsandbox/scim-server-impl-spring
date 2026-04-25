# Contributing

Thanks for contributing to scim-server-impl-spring.

This repository contains the standalone Spring Boot SCIM server
implementation for the SCIM Sandbox project. Keep changes focused on API
behavior, persistence, security, release workflow changes, or
documentation that matches the live repository structure.

## Ground Rules

- Keep each change narrow and intentional.
- Do not mix unrelated refactors into API, persistence, workflow, or
	documentation changes.
- Do not commit bearer tokens, datasource credentials, actuator API keys,
	or generated logs.
- Prefer the existing controller, service, mapper, and repository layout
	over new abstractions unless there is a clear gain.
- Update tests and docs when API behavior, configuration keys, or release
	flow changes.

## Before You Start

1. Check for existing issues or pull requests that already cover the same work.
2. Read [README.md](./README.md) and [SECURITY.md](./SECURITY.md) before changing runtime or security behavior.
3. If the change touches request or response shape, update controller, service, mapper, and tests together.
4. If the change touches release or Docker behavior, keep the workflows, Dockerfile, and docs consistent.

## Working Conventions

- Keep Java sources under `src/main/java/de/palsoftware/scim/server/impl` and tests under the matching `src/test/java` packages.
- Keep SCIM routes workspace-scoped under `/ws/{workspaceId}/scim/v2/**`.
- `workspaceId` route parameters remain UUID-based.
- `/Me` remains a `501 Not Implemented` endpoint unless the repository explicitly gains subject-to-resource mapping.
- Request logging remains workspace-scoped and stores SCIM request and response bodies unless a deliberate security change says otherwise.
- Prefer constructor injection and keep Lombok out of the module.

## Validation

Validate changes before opening a PR.

Common checks:

- run `mvn clean verify`
- if the Testcontainers suite needs a different migration image tag, set `SCIM_DB_IMAGE` or `-Dscim.db.image=...`
- if you changed security or request handling, manually exercise the affected endpoint flow as well

## Pull Request Checklist

- explains the API or persistence change and why it is needed
- updates docs and configuration when runtime behavior or environment keys change
- keeps secrets and machine-specific values out of the diff
- avoids unrelated cleanup
- passes the relevant validation steps

## Reporting Bugs

When reporting a server issue, include:

- the affected endpoint or component
- the request path, method, and payload
- the expected and actual SCIM response
- the relevant environment or configuration details with secrets removed
- the test class or reproduction steps, if known

## Security Issues

Do not report vulnerabilities through public issues. Follow
[SECURITY.md](./SECURITY.md) instead.
