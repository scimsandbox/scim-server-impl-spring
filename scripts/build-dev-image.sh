#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
docker build -t scim-server-impl-spring:dev -t edipal/scim-server-impl-spring:dev .