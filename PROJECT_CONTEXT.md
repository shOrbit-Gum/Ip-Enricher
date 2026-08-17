# Project Context

## Current Scope

The current milestone is a Shodan-only defensive infrastructure-enrichment
tool. It returns small, high-confidence candidate pools using deterministic
exact or compound indicators. Masscan, Nmap, and active verification are
future work.

## Shodan Usage Decisions

The expected account is a basic paid plan with 100 monthly query credits.
The implementation will:

- Check `/api-info` once per run.
- Call the free count endpoint before every search.
- Search only sufficiently small pools.
- Default to one page and at most 25 results per query.
- Narrow broad queries or stop them instead of downloading large datasets.
- Use a configurable per-run credit limit and stop automatically when reached.
- Never pause for mid-run user authorization.
- Cache identical calls, deduplicate candidates, retain full search responses, and
  perform full host lookups only for shortlisted IPs.
- Handle rate limits with bounded backoff and preserve partial results.
- Record usage evidence without storing the API key.

Shodan-only candidate acceptance is not active verification and does not prove
that a candidate is malicious.

## Guidance Reviewed

- https://developer.shodan.io/api
- https://book.shodan.io/developer-apis/shodan-api/
- https://help.shodan.io/the-basics/credit-types-explained
- https://help.shodan.io/guides/how-to-download-data-with-api