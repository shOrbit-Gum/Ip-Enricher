## Contribution policy

External pull requests and code contributions are not accepted. Unsolicited
external pull requests will be closed; bug reports are welcome through Issues.

This template is for repository-owner pull requests.

## Summary

Describe the change and its defensive-use purpose.

## Validation

- [ ] `uv run pytest`
- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run mypy src`
- [ ] Tests made no real Shodan requests and executed no scanners.
- [ ] No credentials, research data, raw provider outputs, or private targets are included.
- [ ] The Shodan-only scope, deterministic acceptance, provenance, and evidence contracts remain intact.
