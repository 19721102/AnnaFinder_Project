#!/bin/sh
set -euo pipefail

echo "Running alembic upgrade head..."
alembic upgrade head

exec "$@"
