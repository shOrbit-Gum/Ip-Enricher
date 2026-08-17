# Changelog

All notable changes to this project will be documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-15

### Added

- Shodan seed-IP enrichment with raw-response preservation and normalized
  infrastructure profiles.
- Deterministic exact, compound, same-service, and opt-in cross-service
  discovery paths with count-before-search pool guards.
- Credit budgets, bounded pagination and concurrency, request caching,
  deduplication, retry handling, and partial-result evidence.
- Explainable candidate acceptance and scoring with explicit
  `active_verification_status: not_performed` evidence.
- Versioned, atomic filesystem JSON storage and CLI commands for enrichment,
  discovery, batch discovery, and reporting.
- Mocked test coverage for provider, normalization, query, rules, scoring,
  pipeline, storage, configuration, and CLI behavior.

[Unreleased]: https://github.com/shOrbit-Gum/Ip-Enricher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shOrbit-Gum/Ip-Enricher/releases/tag/v0.1.0
