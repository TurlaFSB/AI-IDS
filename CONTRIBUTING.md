# Contributing

Thanks for helping improve AI-IDS. This project follows industry practice for security software:
small reviewable changes, tests for everything, and no shortcuts on quality gates.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues
privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Development setup

Requires Python 3.11+.

```bash
git clone https://github.com/TurlaFSB/AI-IDS.git
cd AI-IDS
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Quality gates

Every change must pass, locally and in CI:

```bash
ruff check src tests
ruff format --check src tests
mypy
pytest            # enforces >= 85% coverage
```

New behaviour ships with tests. Bug fixes ship with a regression test.

## Dependencies and the lock files

Dependencies are declared in `pyproject.toml` and locked with hashes in `requirements/`.
After changing them, regenerate the locks and commit the result:

```bash
pip install --require-hashes -r requirements/tools.txt   # installs the pinned uv
./scripts/lock.sh
```

CI fails if the lock files are out of date. Never edit them by hand.

## Pull requests

1. Fork and branch from `main`.
2. Keep the change focused; unrelated cleanups belong in their own PR.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
4. Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
5. Record significant design decisions as an ADR in `docs/adr/`.
6. Fill in the pull request template. CI must be green.

## Rules that are never negotiable

- **No secrets, datasets, packet captures, or trained models in the repository.**
- **No loading model artifacts from untrusted sources.** Artifacts are pickle-based; see the
  threat model.
- **Evaluation integrity:** no random train/test splits on flow data, no tuning on the test set,
  and report false-positive rate and per-class recall, not accuracy alone.
- **Defensive scope only:** detection, alerting, and response. No exploit or attack tooling.
