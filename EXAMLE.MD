This is an Example ran on AUG 11th 2026

Original report by Check Point: https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/

Command: IP-Enricher discover 45.137.205.53 -f table

  Investigation: 1605af04650a41f0bd03b6a2bfe068a0
  Seed: 45.137.205.53
  Candidates discovered: 6

  Candidate       AS        Score  Rule                             Pool  Why it matched
  --------------  --------  -----  -------------------------------  ----  ----------------------------------------------------------------------
  62.3.53.79      AS212477  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
  91.190.100.152  AS212477  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
  156.227.0.19    AS149440  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
  166.88.132.106  AS149440  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
  166.88.198.40   AS149440  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
  178.20.206.89   AS198691  120    exact_tls_fingerprint (2 rules)  7     Same TLS certificate on 443/tcp; HTTP title "404 Not Found" on 443/tcp
