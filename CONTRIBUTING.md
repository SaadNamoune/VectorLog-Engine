# Contributing to VectorLog-Engine

Thank you for your interest. Contributions are welcome via pull requests.

## Setup

```bash
git clone https://github.com/SaadNamoune/VectorLog-Engine.git
cd VectorLog-Engine
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
docker compose up -d
```

## Running Tests

```bash
pytest tests/ -q
```

Unit tests (parsers, threat_intel, text) run without any external services.
Integration tests require the Docker stack (`docker compose up -d`).

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting:

```bash
ruff check src/ tests/
```

Line length: 100. Target: Python 3.10+.

## Pull Request Guidelines

- One feature or fix per PR
- Add tests for any new public function
- Update `ARCHITECTURE.md` if you change the data flow or add a new module
- Keep commit messages in the form `type: short description` where type is one of: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `build`, `perf`

## Reporting Issues

Open an issue at [github.com/SaadNamoune/VectorLog-Engine/issues](https://github.com/SaadNamoune/VectorLog-Engine/issues) with:
- Python version
- OS
- Minimal reproduction steps
- Expected vs actual behavior
