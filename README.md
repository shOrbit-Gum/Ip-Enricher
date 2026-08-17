# IP Enricher

[![Python 3.12 and 3.13](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/shOrbit-Gum/Ip-Enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/shOrbit-Gum/Ip-Enricher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/shOrbit-Gum/Ip-Enricher)](https://github.com/shOrbit-Gum/Ip-Enricher/releases)

IP Enricher is a defensive Shodan-based threat-intelligence tool. It enriches
one or more seed IP addresses, extracts exact and compound technical
indicators, and discovers small, explainable groups of hosts that share those
indicators. Results are deterministic and evidence-backed: a match supports a
discovery rule, but does not by itself establish maliciousness or prove that a
service is currently reachable.

## Quick start

Requirements: Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --locked
$env:SHODAN_API_KEY = "your-key"
Copy-Item config.example.yaml config.local.yaml
```

Keep the API key in the environment. Never place it in YAML, source files,
logs, fixtures, or stored investigation artifacts.

Run the CLI with a documentation-range address while testing:

```powershell
ip-enricher enrich 192.0.2.10 --config config.local.yaml
ip-enricher discover 192.0.2.10 --config config.local.yaml
ip-enricher discover 192.0.2.10 --xs --config config.local.yaml
ip-enricher discover 192.0.2.10 --format table --config config.local.yaml
ip-enricher discover-batch --input seeds.txt --format table --config config.local.yaml
ip-enricher discover-batch --input seeds.txt --xs --config config.local.yaml
ip-enricher report <investigation-id> --format table --config config.local.yaml
```

`enrich` retrieves and normalizes a seed without discovery. `discover` also
runs same-service correlation. Same-service pair and triple queries are
enabled by default and are scoped to one observed service. Cross-service
correlation is opt-in with `--xs`. `discover-batch` reads one IPv4 address per
line, ignores blank lines and `#` comments, removes duplicates while retaining
input order, and shares one configured credit budget across the batch.

The default table output is a concise analyst view of candidates, scores,
rules, pool sizes, and matching evidence. Use `--format json` for complete
machine-readable output and diagnostics. Stored JSON remains the authoritative
evidence.

### Install from a GitHub Release

Each version tag creates a GitHub Release containing a wheel, source archive,
and `SHA256SUMS`. Download the wheel for the release, verify its checksum, and
install the local artifact:

```powershell
Get-FileHash .\ip_enricher-0.1.0-py3-none-any.whl -Algorithm SHA256
python -m pip install .\ip_enricher-0.1.0-py3-none-any.whl
ip-enricher --help
```

Compare the reported hash with `SHA256SUMS` before installing.

## Configuration

Copy `config.example.yaml` to the ignored `config.local.yaml` and change
operational settings for the run. Keep all real investigation output outside
the repository. For example, create a permanent directory such as
`C:\Users\<you>\Documents\IP-Enricher-Research\investigations` and set an
absolute path:

```yaml
storage:
  root: C:\Users\<you>\Documents\IP-Enricher-Research\investigations
```

The repository-relative storage value in `config.example.yaml` is suitable only
for documentation-range demonstrations; the entire `data/` tree and local
configuration files are ignored as a second line of defense. Do not use the
repository as storage for real research.

The important discovery defaults are:

```yaml
discovery:
  max_query_credits_per_run: 10
  max_results_per_query: 25
  max_pages_per_query: 1
  max_candidate_pool: 50
  max_xs_source_count: 150000
  max_candidates_per_rule: 50
```

The search-result and candidate limits bound automatic expansion. A search
retrieves at most 25 results and one page by default. The XS source limit is a
pre-retrieval guard: a source count above `150000` is recorded and stopped,
without downloading its IP set. All values are configurable in YAML; the
configured values govern discovery and acceptance.

## Credit-aware discovery

At the start of a run the client checks Shodan account information. Before each
paid host search it performs the free count request and searches only when the
reported pool can fit the configured candidate limit and the remaining
per-run budget. Searches are bounded to one page by default and result sets
are deduplicated. Identical requests are cached within an investigation.
When the budget or available account credits cannot support a path, the path is
stopped cleanly and the reason is preserved in the evidence.

Cross-service correlation first counts each source. Sources within the
configured limit are collected using the free `ip` facet where possible, with
bounded `fields=ip_str` pagination as a fallback. Complete source sets are
intersected pairwise and then, when needed, with a third source. Full host
profiles are retrieved only for a final intersection that fits the candidate
limit. Incomplete or truncated intersections are rejected.

## Evidence and storage

Each investigation is stored as versioned UTF-8 JSON under
`storage.root` (by default `data/investigations/<investigation-id>/`). The
artifacts preserve, as applicable:

- raw Shodan host and search responses;
- normalized seed observations and extracted indicators;
- exact query text, rule name/version, counts, pages, retrieval method, and
  credit accounting;
- candidate observations, matching indicators, deterministic scores, and the
  explanation for each score contribution;
- errors, stopped paths, and final reports.

Writes use temporary files followed by atomic replacement. Secret-named fields
and API keys are excluded from persisted data. Candidate records include
`active_verification_status: not_performed`; this identifies the evidence
source accurately and should not be read as a live-network confirmation.

### SSH fingerprint note

SSH host-key fingerprints are normalized and retained in the seed and host
evidence, and they contribute to evidence inspection where present. They are
excluded from discovery queries because a live validation showed that Shodan's
normalized fingerprint query returned zero results for a seed record that
contained the same fingerprint. Until Shodan provides a reliable searchable
representation, using that field for discovery would create incomplete and
misleading candidate pools.

## Defensive-use scope and limitations

The tool uses Shodan observations as its evidence source. Provider failures,
rate limits, incomplete responses, and budget stops are recorded rather than
silently ignored. Common attributes such as a port, operating system, or
generic product do not independently qualify a candidate. Exact and compound
rules, pool limits, and fixed indicator weights determine acceptance; no
unrecorded analyst judgment or machine-learning score is applied.

Use only documentation ranges in examples and tests:
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.

This software is intended only for lawful defensive security research on
systems and data you are authorized to investigate. It does not determine
maliciousness, provide live-network verification, or grant authorization to
access any system. You are responsible for complying with applicable law,
provider terms, and organizational policy.

## Project policy

Bug reports are welcome through GitHub Issues. External pull requests and code
contributions are not accepted; see [CONTRIBUTING.md](CONTRIBUTING.md).
Potential vulnerabilities must be reported privately as described in
[SECURITY.md](SECURITY.md). This project is released under the
[MIT License](LICENSE), and release history is recorded in
[CHANGELOG.md](CHANGELOG.md).

## Development

```powershell
uv run pytest
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv build
```

Tests use mocked providers and sanitized fixtures. They must not contact
Shodan, consume API credits, or execute network scanners.

## FOR AGENTS

Before changing this repository, read `AGENTS.md` in full and inspect the
affected modules, tests, configuration, and stored-artifact contracts. That
file is the authoritative engineering and scope guide.

Agents working on this project must preserve these rules:

- Keep the runtime Shodan-only and deterministic. Candidate acceptance must be
  driven by configured rules, pool limits, required indicators, and fixed
  scores—not model judgment.
- Never make real Shodan requests in automated tests. Use mocked providers and
  sanitized documentation-range fixtures.
- Preserve count-before-search ordering, one-page/default result bounds,
  per-run credit limits, request caching, deduplication, and complete evidence
  for every discovery path. Do not bypass a pool guard to obtain more results.
- Keep same-service correlation enabled by default and cross-service
  correlation opt-in through `--xs`. Do not use SSH fingerprints to construct
  discovery queries; preserve them as evidence and retain the documented
  self-match limitation.
- Keep enrichment, normalization, indicator extraction, query construction,
  discovery, acceptance, scoring, storage, and CLI responsibilities separate.
  Do not add scanners or a scanner/runners subsystem.
- Never commit API keys, `.env` files, raw provider outputs, investigation
  directories, exports, or sensitive logs. Review generated files before
  publishing the project.
- Preserve versioned JSON schemas, atomic writes, provenance, exact queries,
  counts, rule versions, and `active_verification_status:
  not_performed` in candidate evidence.
- After changes, run the focused tests and then `uv run pytest`,
  `uv run ruff check .`, and `uv run mypy src`. Confirm that no test made an
  external request and that no scanner integration was introduced.
