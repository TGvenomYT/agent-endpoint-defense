# Changelog

Version history of the defense described in the paper. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions track the paper's
Guardian/Bastion/Mirage progression.

## Paper corrections — 2026-11-03
### Fixed
- **Stress-suite attribution (C10, H1, H9).** These categories sent every
  payload to `shell_explain`, which Bastion exempts from injection checks, and
  the harness records only HTTP status (a Bastion block is a JSON-RPC error
  inside HTTP 200). Their HTTP outcomes were Guardian bans carried over from
  earlier categories, not content-defense results. The earlier claims ("0% of
  WAF-evasion payloads blocked", "90% false positives", "zero false negatives
  in C10") are withdrawn. Measured directly on the same payloads
  (`artifact/stress_bastion_direct.py`), Bastion blocks 87.0% of WAF-evasion
  and 80.0% of plain injection payloads, with 6.7% false positives on
  adversarially worded and 0% on ordinary benign inputs.
- Standard-mode table: C2 served 69 → 46 (401s had been counted as served);
  total served 124,762 → 124,739.
- Bibliography: corrected authors for MCPTox, MCP-ITP, TrustShiftProbe, the
  MCP threat-modeling paper, MCP Safety Audit and CASCADE; corrected venue for
  the Tamayo review (LNNS) and year/volume for Hou et al. (TOSEM 35(10), 2026).

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
