#!/usr/bin/env bash
# Regenerate the hash-locked requirement files from pyproject.toml.
# Requires uv (pip install uv). The lock is universal: one file covers Python 3.11-3.13
# on Linux, macOS and Windows. Review the diff before committing.
# The pinned uv itself is locked separately in requirements/tools.txt (bump it by editing
# requirements/tools.in and recompiling).
set -euo pipefail
cd "$(dirname "$0")/.."

uv pip compile pyproject.toml --universal --generate-hashes --python-version 3.11 \
  --no-header -o requirements/runtime.txt
uv pip compile pyproject.toml --extra dev --universal --generate-hashes --python-version 3.11 \
  --no-header -o requirements/dev.txt
