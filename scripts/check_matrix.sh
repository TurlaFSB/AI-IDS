#!/usr/bin/env bash
# Run the CI quality gates locally on each supported Python version, using the same
# hash-locked install as CI. Usage: scripts/check_matrix.sh [3.11 3.12 3.13]
# Requires uv (see requirements/tools.txt); uv fetches interpreters it does not find.
set -euo pipefail
cd "$(dirname "$0")/.."

versions=("$@")
if [ "${#versions[@]}" -eq 0 ]; then
  versions=(3.11 3.12 3.13)
fi

for version in "${versions[@]}"; do
  echo "=== Python ${version} ==="
  env_dir=".venv-matrix/py${version}"
  uv venv --quiet --python "${version}" "${env_dir}"
  uv pip install --quiet --python "${env_dir}/bin/python" --require-hashes -r requirements/dev.txt
  uv pip install --quiet --python "${env_dir}/bin/python" --no-deps -e .
  "${env_dir}/bin/ruff" check src tests
  "${env_dir}/bin/ruff" format --check src tests
  "${env_dir}/bin/mypy"
  "${env_dir}/bin/pytest" -q
done
echo "All requested Python versions passed."
