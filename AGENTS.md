# AGENTS.md

## Mission

Build a defensive cyber-threat-intelligence tool that enriches suspected
malicious IP addresses and identifies additional infrastructure sharing
high-confidence technical characteristics.

The current milestone uses Shodan data only. It starts with one or more seed
IPs, builds a normalized Shodan infrastructure profile, extracts searchable
indicators, discovers matching IPs through Shodan, and returns small,
explainable candidate sets.

Prioritize fewer, stronger candidates over broad similarity results.

## Current Scope

Implement now:

- Seed-IP input and validation
- Shodan host enrichment
- Shodan response preservation and normalization
- Exact and compound indicator extraction
- Deterministic Shodan query construction
- Candidate-pool measurement and narrowing
- Candidate discovery through Shodan
- Explainable candidate acceptance and scoring
- Filesystem-based JSON investigation storage
- CLI commands for enrichment, discovery, and reporting

Do not implement Masscan or Nmap runners in the current milestone. Active
network verification is a future feature.

## Core Principles

- Return fewer, stronger candidates rather than many weak matches.
- Use deterministic, configurable rules instead of subjective agent judgment.
- Preserve the evidence connecting every candidate to its seed.
- Record the exact Shodan query and rule that produced each candidate.
- Never label a candidate malicious solely because it resembles a seed.
- Keep thresholds, indicator rules, and acceptance requirements configurable.
- Do not imply that Shodan-only evidence is a live network confirmation.

Agents implement configured rules. They must not decide case-by-case whether an
indicator feels distinctive or whether a candidate looks malicious.

## Current Investigation Flow

For each seed IP:

1. Validate the seed IP.
2. Retrieve its Shodan host data.
3. Preserve the raw Shodan response.
4. Normalize the response into an infrastructure profile.
5. Extract exact and compound searchable indicators.
6. Build deterministic discovery queries from configured rules.
7. Query Shodan for IPs sharing those indicators.
8. Reduce broad result sets by adding compatible seed indicators.
9. Reject discovery paths that cannot meet configured pool limits.
10. Apply deterministic acceptance and scoring rules.
11. Store candidates with the exact evidence explaining every match.
12. Present the candidate IPs and relevant limitations.

Candidate expansion must remain bounded by configured limits or analyst
selection. Do not recursively enrich every result automatically.

## Future Feature: Masscan and Nmap Runners

Masscan and Nmap integration is explicitly deferred. Do not implement, install,
invoke, mock, or add runtime configuration for these tools unless the user
starts that milestone.

When that milestone is authorized:

- Treat Masscan and Nmap as existing external programs.
- Build thin subprocess adapters; do not implement scanning behavior in Python.
- Use argument arrays and never use `shell=True`.
- Use Masscan for port discovery.
- Use Nmap for targeted service inspection.
- During seed enrichment, inspect Masscan-open ports absent from Shodan.
- During candidate verification, inspect only ports relevant to the discovery
  rule.
- Add explicit verification states without changing historical Shodan evidence.

Do not create placeholder runner modules merely to anticipate this feature.
Reserve clean interfaces only where current code genuinely needs them.

## Normalized Infrastructure Profile

The Shodan-derived profile should support fields Shodan can provide, including:

- IP address
- Open ports and transport protocols
- Service names, products, and versions
- Raw and normalized banners and banner hashes
- TLS certificate fields and fingerprints
- HTTP titles, headers, redirects, favicon hashes, and content hashes
- SSH host keys
- Hostnames and domains
- Operating-system hints
- ASN, organization, ISP, and network prefix
- Shodan tags and vulnerabilities
- Shodan observation time when supplied
- Collection time
- Source attribution

Preserve the raw response and the source of every normalized observation. Do not
silently merge conflicting values or require fields Shodan cannot reliably
provide.

## Indicator Types

### Exact Indicators

The following can be strong indicators when exact, searchable, and uncommon:

- TLS certificate fingerprints
- SSH host-key fingerprints
- Exact distinctive banner hashes
- Exact HTTP content hashes
- Exact favicon hashes
- Exact service fingerprints
- Other stable cryptographic or content-derived identifiers

An exact match is not automatically rare. Rarity is measured using the complete
result count reported by Shodan.

### Compound Indicators

Common attributes must not independently qualify as high-confidence evidence.
Combine compatible indicators to reduce the result pool, for example:

- Service product and exact version
- Port, product, and version
- Port, product, and banner fragment
- HTTP title and favicon hash
- Certificate subject and issuer
- Hostname pattern and service fingerprint
- A distinctive combination of open ports
- ASN combined with a specific service characteristic

Generic attributes such as port 80, port 443, HTTP, SSH, Linux, a cloud
provider, or a common web-server product are insufficient by themselves.

### Distinct Port or Service Indicators

A seed may expose an unusual port, product, protocol, or service combination.
For the current Shodan-only discovery path:

1. Construct a Shodan query for the characteristic.
2. Retrieve matching IPs and the complete result count.
3. Add compatible seed indicators when the result set exceeds the configured
   limit.
4. Retain only results whose Shodan records contain every characteristic
   required by the discovery rule.
5. Record that active network verification was not performed.

Do not describe a Shodan observation as proof that a service is currently live.

## Candidate-Pool Rules

High confidence must be based on measurable configuration. Configuration should
define:

- Maximum results for a single-indicator query
- Maximum results after compound filtering
- Maximum candidates retained per rule
- Indicators allowed to qualify independently
- Allowed indicator combinations
- Minimum number of independent matching indicators
- Indicator weights
- Maximum investigation depth

When a query exceeds the configured pool limit:

1. Do not accept the result set as candidates.
2. Add another compatible indicator from the seed profile.
3. Query again or intersect complete result sets.
4. Continue until the pool is within the limit.
5. Stop that discovery path if no supported combination is sufficiently small.

Do not invent thresholds dynamically. Record the configured rule and thresholds
used for every discovery path.

## Shodan Discovery

Keep Shodan seed enrichment separate from Shodan candidate discovery.

Record for every discovery query:

- Seed IP
- Indicator or indicator combination
- Exact query representation
- Complete result count reported by Shodan
- Retrieved IPs
- Collection time
- Pagination and result-limit information
- Errors or incomplete-result conditions

Do not treat a truncated result set as proof that an indicator is rare. Prefer
server-side query combinations where supported; otherwise intersect complete
result sets locally. Cover every query builder with tests.

## Candidate Acceptance and Evidence

Candidate acceptance in the current milestone means that the candidate passed a
deterministic Shodan-based discovery rule. It does not mean the infrastructure
was actively verified or proven malicious.

Each retained candidate must include:

- Seed and candidate IPs
- Discovery rule name and version
- Exact Shodan query that discovered it
- Matching indicators
- Reported candidate-pool size
- Relevant Shodan observations
- Observation and collection times when available
- Deterministic score
- Explanation of every scoring contribution
- `active_verification_status: not_performed`

Incomplete or truncated discovery results must not pass a rule that requires a
complete pool count.

## Scoring

Scoring ranks candidates that passed an explicit discovery rule. It does not
replace pool limits or acceptance requirements.

Use fixed, configurable indicator weights. Exact identifiers should normally
outweigh descriptive attributes. Reward independent indicator groups and avoid
double-counting correlated representations of the same evidence. Apply no
unrecorded judgment adjustments.

Do not introduce machine learning without labeled data and a defined evaluation
method.

## Discovery Rules

Represent searches as named, versioned rules. Each rule defines:

- Required seed fields
- Shodan query construction
- Maximum acceptable result-pool size
- Optional narrowing indicators
- Shodan-record acceptance conditions
- Scoring contributions

Initial rule concepts may include:

- `exact_tls_fingerprint`
- `exact_ssh_host_key`
- `exact_banner_hash`
- `favicon_and_http_title`
- `port_product_and_version`
- `distinct_service_fingerprint`
- `rare_port_and_banner`

Make rules data-driven where practical. Store the rule name and version with
every result.

## Architecture

Keep these current responsibilities separate:

- `models`: normalized entities, observations, and evidence
- `providers`: Shodan host enrichment and search
- `pipeline`: seed enrichment and discovery orchestration
- `indicators`: exact and compound indicator extraction
- `query`: Shodan query construction
- `discovery`: candidate retrieval and result-set intersection
- `rules`: deterministic discovery and acceptance rules
- `scoring`: explainable candidate ranking
- `storage`: investigation artifacts and evidence
- `cli`: user-facing commands

Core investigation logic must not depend on the CLI or a specific storage
implementation. Do not add a `runners` subsystem during the current milestone.

## Agent and Model Orchestration

Use a coordinator-and-workers model for repository development. The primary
agent owns architecture, task decomposition, security-sensitive decisions,
cross-module review, final integration, validation, and user communication.
Delegation does not transfer responsibility for correctness.

### Model Roles

- `gpt-5.6-sol`: coordinator, architecture, difficult debugging, cross-module
  review, acceptance semantics, and final integration
- `gpt-5.6-terra`: normal feature implementation, Shodan normalization, query
  construction, refactoring, and focused review
- `gpt-5.6-luna`: fixtures, routine tests, documentation updates, formatting,
  and bounded inspection

These are preferences rather than correctness guarantees. If a preferred model
is unavailable, preserve the role boundaries with an available model.

### Delegation Rules

Delegate only concrete, bounded, independently executable work that is easy to
verify and does not require unresolved architectural decisions. Avoid assigning
multiple workers to the same files.

Suitable delegated work includes Shodan fixture normalization, query-builder
tests, sanitized fixtures, settled documentation, bounded inspection, and
focused review behind an agreed interface.

The coordinator retains final decisions about architecture, candidate
acceptance, discovery rules, confidence thresholds, provenance, cross-subsystem
contracts, ambiguous requirements, integration, validation, and user-facing
conclusions.

Every delegated task must specify its objective, files in and out of scope,
interfaces to preserve, expected output, required tests or evidence, edit
permission, stopping conditions, and questions to return.

### Parallel Work

Use parallel workers only after shared interfaces are defined. Shodan
normalization, JSON storage, and independent query-rule tests are suitable
parallel tasks. Concurrent edits to shared pipeline code, shared fixtures, or
unresolved interfaces are not.

Workers must stay within scope, avoid unrelated changes, report conflicts, run
focused tests, and return a concise summary with evidence. Tests must not make
real Shodan requests. Workers must not delegate further unless the coordinator
explicitly permits it.

### Review and Integration

The coordinator reviews delegated work for contract compliance, interface
compatibility, malformed-input handling, provenance, determinism, test quality,
unrelated edits, and accidental external calls. The coordinator then runs the
relevant combined tests; worker tests do not replace integration validation.

### Application Runtime Is Not Agent Work

Do not use language-model agents merely to call Shodan, parse known formats,
intersect results, apply thresholds, calculate deterministic scores, or write
JSON artifacts. Implement these as ordinary Python code.

The runtime must require no model judgment for candidate acceptance. A model
may later produce analyst-facing summaries, but its narrative must not alter
discovery or acceptance results.

## Storage

Use filesystem-based JSON artifacts for the initial implementation.

Store each investigation in a separate directory and preserve:

- Investigation metadata
- Seed profiles
- Raw Shodan responses
- Normalized observations
- Extracted indicators
- Shodan discovery queries and result counts
- Candidate acceptance results
- Relationship evidence
- Final reports

Use stable identifiers, deterministic paths, atomic file replacement, and
versioned schemas. Keep storage behind an interface so a database can be added
if cross-investigation querying or scale creates a concrete need.

Do not introduce SQLite, PostgreSQL, or a graph database without a requirement
that the file-based store cannot satisfy.

## Shodan API Usage

The project targets a basic paid Shodan plan with 100 monthly query credits.
Use simple automatic controls to avoid wasting credits.

- Call `/api-info` once at the start of a run and record available query credits.
- Call `/shodan/host/count` before every `/shodan/host/search`; count does not
  consume query credits.
- Run a search only when the reported pool is within the configured candidate
  limit. Narrow broad queries with another compatible seed indicator or stop
  that discovery path.
- Default to at most 25 search results and one result page per query.
- Do not implement unlimited downloads or automatic broad pagination.
- Keep a configurable per-run credit limit and stop cleanly when it is reached.
- Do not ask for user authorization during a run. Return the completed partial
  result and the reason a discovery path stopped.
- Do not use Shodan response-field projection; retain the full search response as evidence.
- Deduplicate candidate IPs before full host lookups.
- Cache identical host lookups, count queries, and search pages within an
  investigation.
- Bound request concurrency. Honor `Retry-After` and use bounded backoff for
  rate limits and transient server failures.
- Do not retry invalid queries, authentication failures, or plan-limit errors.
- Record sanitized queries, counts, pages, retrieved totals, cache use, and
  errors. Never record the API key.

Configuration should include `max_query_credits_per_run`,
`max_results_per_query`, `max_pages_per_query`, and
`max_concurrent_shodan_requests`. Defaults should favor a small credit footprint
and high-confidence candidate pools.

Tests must prove count-before-search ordering, one-page/default-result limits,
per-run budget stopping, cache reuse, deduplication, and rate-limit handling.
## Configuration

Current configuration should support:

- Shodan API key through an environment variable
- Shodan request timeout and retry behavior
- Maximum discovery result-pool size
- Maximum candidates retained per rule
- Minimum independent indicator count
- Indicator weights
- Enabled discovery rules
- Rule-specific acceptance requirements
- Investigation-depth limits
- Storage location

Do not add Masscan or Nmap configuration in the current milestone. Do not
hard-code credentials, thresholds, or target lists.

## Engineering Rules

- Use Python 3.12 or newer.
- Use typed models and function signatures.
- Validate IP addresses and provider inputs.
- Retain raw Shodan results for debugging and reprocessing.
- Keep collection, normalization, discovery, acceptance, and scoring separate.
- Make partial seed enrichment usable while recording provider failures.
- Reject discovery paths when mandatory evidence is incomplete.
- Use structured errors rather than silently ignoring failures.
- Prefer deterministic, testable behavior and readable code.
- Avoid abstractions that do not advance the current investigation workflow.
- Do not implement future runner functionality preemptively.
- Update tests and documentation when pipeline behavior changes.

## Testing

Automated tests must not contact Shodan or execute real network scans. Use
mocked providers and sanitized fixtures.

Test at least:

- Shodan host-data normalization
- Shodan query construction for every discovery rule
- Exact and compound indicator extraction
- Candidate-pool limits and result-set intersection
- Truncated Shodan result handling
- Rejection of incomplete discovery paths
- Shodan-record acceptance conditions
- Evidence preservation and rule versioning
- Deterministic score calculation
- `active_verification_status: not_performed`
- Prevention of unbounded recursive expansion
- Partial provider failures
- JSON schema migration or rejection behavior
- Atomic storage writes and recovery from incomplete artifacts

Do not add Masscan/Nmap adapters, parsers, fixtures, configuration, or tests in
the current milestone.

Use documentation address ranges in fixtures:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`
- `2001:db8::/32`

## Secrets and Generated Data

Never commit:

- API keys or credentials
- `.env` files
- Raw provider outputs
- Investigation directories or exports
- Logs containing sensitive investigation data

Commit only sanitized examples and fixtures.

## Working on This Repository

Before changing code:

1. Read this file and the relevant modules.
2. Confirm the work belongs to the current Shodan-only milestone.
3. Trace the affected investigation flow.
4. Identify the discovery and acceptance rules involved.
5. Preserve separation between enrichment, discovery, and scoring.

After changing code:

1. Run relevant tests.
2. Run the complete test suite when practical.
3. Run formatting, linting, and type checking.
4. Confirm tests did not invoke Shodan or real scanners.
5. Confirm candidate decisions remain deterministic and evidence-backed.
6. Confirm no Masscan/Nmap runner work was introduced.
7. Summarize changed behavior and known limitations.

When implementation details are unclear, choose the simplest design supporting
deterministic high-confidence Shodan discovery. Ask for clarification when a
choice would alter candidate acceptance rules or investigation scope.