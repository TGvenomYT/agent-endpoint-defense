# Changelog

Version history of the defense described in the paper. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions track the paper's
Guardian/Bastion/Mirage progression.

## [5.0.0] — 2026-10-22 — Mirage (v5)
### Added
- **Risk-adaptive, in-band routing.** A sequential CUSUM session-risk estimator
  with a frozen-after-warmup noise model and in-band-only baseline adaptation
  (an adversary cannot walk the baseline along with a slow attack).
- **Graded execution lanes** — `PRIMARY`, `THROTTLED`, `SHADOW`, `DECEPTION` —
  with a format-matched synthetic shadow lane run from the tool's own code, and
  sticky hysteresis.
- **Verifiable result provenance** — HMAC Merkle-chained, lane-bound; verified
  before model-context admission.
- Deployed loopback evidence service: 0/1,800 benign false-shadow; low-and-slow
  contained after 8 calls; +5.6 µs/request.

## [4.0.0] — Bastion (v4)
### Added
- Post-auth content defense: input validation (size/schema/injection), behavioral
  analysis (enumeration, tool cycling), output secret redaction (9 formats).
- Active deception: honeytoken injection with a canary callback endpoint.
- JSON-RPC batch-size cap (closes the batch rate-limit bypass).

## [3.0.0] — Guardian v3
### Added
- Scoped bearer tokens (per-tool capability).
- Per-(source, tool) sliding-window rate limiting.

## [2.0.0] — Guardian v2 (hardening)
### Changed
- All state keyed on a network **source** (IPv4 or IPv6 /64), LRU-capped at 20k.
- Ban list mtime-cached (169× faster at 50k bans); exponential auth-failure
  backoff; path-scan banning; forwarding headers trusted only from loopback.

## [1.0.0] — Guardian v1 (initial public release) — 2026-09-27
### Added
- Pre-auth admission gate: ban list, 38 crawler/scanner UA signatures,
  source rate limiting; constant-time bearer auth; capability filter.
