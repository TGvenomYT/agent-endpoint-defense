# Features

A single-operator, dependency-free (standard library only) full-stack defense
for an Internet-exposed MCP agent endpoint.

## Guardian — pre-authentication admission gate
- Unexpired-ban check (`403`) and 38 crawler/scanner User-Agent signatures.
- Source-keyed rate limiting (IPv4 or IPv6 /64), LRU-bounded at 20,000 sources.
- Constant-time bearer-token auth; `fail2ban`-style auth-failure banning with
  exponential backoff and an optional operator allowlist.
- Capability filter: `local_only` and denylisted tools removed from
  `tools/list` and `tools/call`.
- mtime-cached ban list; path-scan banning; forwarding headers trusted only
  from a loopback peer.

## Guardian v3 — credential blast-radius control
- Scoped tokens (per-tool capability).
- Per-(source, tool) sliding-window rate limits.

## Bastion — post-authentication content defense
- Input validation: size caps, JSON-Schema conformance, structural
  injection detection (SQL / command / path traversal).
- Behavioral analysis: enumeration and tool-cycling detection.
- Output filtering: redaction of 9 secret formats.
- Active deception: honeytoken injection with a canary callback.

## Mirage (v5) — risk-adaptive routing
- Self-calibrating CUSUM session-risk estimator (no fixed thresholds).
- Graded in-band lanes: primary / throttled / synthetic shadow / deception.
- Format-matched synthetic twin run from the tool's own code.
- Merkle-chained, lane-bound result provenance, verified before context admission.
