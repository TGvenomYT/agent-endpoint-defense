# Guarding the Door

**Measuring and Hardening Lightweight Full-Stack Defense for an Internet-Exposed MCP Agent Endpoint**

Niranjan R. · Department of Artificial Intelligence and Data Science,
KPR Institute of Engineering and Technology (KPRIET), Arasur, Coimbatore ·
`niranjan.r.dev@proton.me`

---

An MCP server published on a public hostname inherits every property of an
Internet service: scanners find it, AI crawlers hit it, and others probe it for
credentials — but unlike a static site, the thing behind the door can *act*.
This paper studies the full request lifecycle of a single-operator,
Internet-exposed [Model Context Protocol](https://modelcontextprotocol.io)
endpoint and asks what one person can realistically put in front of it with no
external dependencies.

It presents a deployed, standard-library-only defense evaluated on real traffic
and a 2,000,000-request stress suite:

- **Guardian** — a pre-auth admission gate (ban list, bot-UA signatures,
  source-keyed rate limiting) plus bearer auth and capability minimization.
- **Guardian v2/v3** — source-keyed state, scoped tokens, per-tool limits.
- **Bastion** — post-auth content defense: input validation, behavioral
  analysis, secret redaction, and active-deception honeytokens.
- **Mirage (v5)** — risk-adaptive, in-band routing: a self-calibrating CUSUM
  session-risk estimator routes each authenticated call across graded lanes,
  including a format-matched synthetic *shadow* lane, with Merkle-chained
  per-result provenance. Evaluated on a deployed service (0/1,800 benign
  false-shadow; a low-and-slow adversary contained after 8 calls).

## Repository layout

| Path | What |
|---|---|
| `main.tex` | the paper |
| `preamble.tex` | LaTeX preamble ([Markdown reference](preamble.md)) |
| `mirage.tex`, `mirage-data.tex` | the v5 section and its live-data macros |
| `artifact/` | evaluation harness, stress tooling, replay tooling, generators |
| `public-data/` | aggregate results (`results_v*.json`, `mirage_evidence_report.json`) |
| `refs.bib` | bibliography |

## Build

```sh
tectonic -X compile main.tex
# or: latexmk -pdf main.tex
```

## The system under study

The protected service is **agentkit**, the author's personal MCP tool gateway.
Two of its public components appear in the paper's tool catalog:

- **smart-terminal** — the shell assistant — https://github.com/TGvenomYT/smart-terminal
- **Cortex-Agent** — the personal-memory agent — https://github.com/TGvenomYT/Cortex-Agent

More of the author's work: https://github.com/TGvenomYT

## Citation

```bibtex
@misc{niranjan2026guarding,
  author       = {Niranjan R.},
  title        = {Guarding the Door: Measuring and Hardening Lightweight
                  Full-Stack Defense for an Internet-Exposed MCP Agent Endpoint},
  year         = {2026},
  howpublished = {\url{https://github.com/TGvenomYT/agent-endpoint-defense}},
  note         = {KPR Institute of Engineering and Technology (KPRIET)}
}
```

## License

See [LICENSE](LICENSE).
