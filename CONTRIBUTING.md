# Contributing

Thanks for your interest in this work. Contributions are welcome in the following areas:

## Reproducibility

- **Run the harness on your own MCP endpoint** and report whether the scenarios behave as documented. File an issue with your platform (OS, Python version, tunnel provider) and any divergence from the published results.
- **Replay tooling improvements** — `artifact/analyze_trace.py` and `artifact/gen_realtraffic_tex.py` are designed to be reusable. Bug fixes, performance improvements and better output formatting are welcome.

## New scenarios

The harness (`artifact/harness2.py`) is extensible. If you identify an attack pattern not covered by S1–S12, propose it as an issue first so we can discuss scope, then submit a PR adding the scenario and its expected outcomes for both v1 and v2.

## Related work and citations

If you know of published work on MCP endpoint admission defense (not tool poisoning or prompt injection — those are well-covered in the paper's related work), please open an issue pointing to it.

## What we won't merge

- Changes to the v1 or v2 server code trees used in the evaluation — those are frozen artifacts.
- Raw traffic logs or any data containing client IP addresses.
- Fabricated or synthetic results presented as real measurements.

## Process

1. Fork the repo and create a feature branch.
2. Keep PRs focused — one concern per PR.
3. If adding data or results, include the exact command that produced them.
4. The paper source (`main.tex`, `refs.bib`) follows the existing LaTeX style. Build with `tectonic -X compile main.tex`.

## Code of Conduct

Be respectful. This is a single-author research project; response times may vary.
