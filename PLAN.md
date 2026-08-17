# Implementation Plan

## Current Milestone: Shodan-Only Enrichment

1. Create the Python package, CLI, configuration, typed models, structured
   errors, and versioned JSON investigation storage.
2. Implement a Shodan client for `/api-info`, host lookup, count, and search.
3. Add automatic API controls: count before search, one page and 25 results by
   default, a configurable per-run credit limit, caching, deduplication, bounded
   concurrency, and rate-limit backoff.
4. Preserve and normalize seed host responses, then extract supported exact and
   compound indicators.
5. Implement named discovery rules that narrow broad Shodan queries or stop the
   discovery path.
6. Retrieve small candidate pools, re-check candidate host profiles, score them
   deterministically, and store complete evidence.
7. Mark candidates with `active_verification_status: not_performed` and produce
   a human-readable summary.
8. Test the entire workflow with mocked Shodan responses and no external calls.

Masscan, Nmap, active verification, and runner-related code remain deferred.