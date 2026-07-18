# Contributing

Thanks for contributing. This project handles a PHI-shaped data model, so code
quality and the compliance test suite are enforced in CI.

## Prerequisites

- Python 3.12+
- Node.js 20+
- PostgreSQL 16 (for running the integration tests locally)

## Backend

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
```

Tooling (all enforced in CI):

```bash
ruff format .          # format
ruff format --check .  # verify formatting
ruff check .           # lint
ruff check --fix .     # lint + autofix
pytest tests/ -q       # unit tests (integration tests skip without a DB)
```

To run the integration tests locally, point them at a throwaway Postgres:

```bash
export TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/hipaa_test
pytest tests/ -q
```

## Frontend

```bash
cd frontend
npm install
```

Tooling (all enforced in CI):

```bash
npm run format         # Prettier write
npm run format:check   # verify formatting
npm run lint           # ESLint
npm run lint:fix       # ESLint autofix
npm run build          # production build
```

## Pre-commit hooks (recommended)

Run the formatters and linters automatically before each commit:

```bash
pip install pre-commit
pre-commit install
```

Config lives in `.pre-commit-config.yaml`.

## Guidelines

- **Never commit secrets.** The `secrets/` directory and `.env` files are
  gitignored. Recovery material stays out of the repo.
- **Don't weaken a safeguard.** The compliance suite (`backend/tests/`) fails the
  build if a PHI route loses auth, a sensitive column loses encryption, the audit
  chain becomes unkeyed, config stops failing closed, etc. If you change one of
  these, update the test and `COMPLIANCE.md` deliberately.
- **Migrations:** schema changes go through Alembic (`alembic revision
  --autogenerate`), not `create_all`.
- Keep the docs (`README`, `COMPLIANCE.md`, `SECURITY.md`) in sync with behavior.
