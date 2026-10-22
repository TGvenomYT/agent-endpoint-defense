# Benchmarks

All figures are measured, not estimated. Sources: `artifact/` harnesses,
`public-data/*.json`, and the deployed Mirage service
(`public-data/mirage_evidence_report.json`).

## Admission gate (Guardian)

| Metric | v1 | v2 |
|---|---|---|
| Gate overhead (median, empty ban list) | +5 µs | +9 µs |
| Median latency at 50,000 active bans | 21.7 ms | **0.13 ms** (169× faster) |
| Rate-state memory at 100,000 sources | 87.4 MB | **18.8 MB** (capped at 20k) |

## Real traffic (time-boxed public exposure)

- 20,977 requests over ~23 h; 96% HTTP-library/CLI clients.
- Unwanted traffic blocked at the gate: **v1 80.4%**, **v2 99.9%**.

## Stress evaluation

- **2,000,000 requests** across 20 traffic and adversarial categories.
- **Zero false blocks** on benign sessions.
- Bastion content defense: 0/50 false positives on natural-language inputs;
  25/25 expected evasion payloads blocked (5 documented regex bypasses).

## Mirage (v5), deployed loopback service

| Metric | Result |
|---|---|
| Benign false-shadow (1,800 requests) | **0 (0.0%)** |
| Low-and-slow adversary contained after | 8 calls |
| Overt anomaly | isolated immediately; 0 real-data leaks |
| Added hot-path overhead | ~5.6 µs/request (stdlib Python) |
| Verify a 1,000-call provenance chain | 2.4 ms |
