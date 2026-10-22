# Preamble reference

Markdown mirror of `preamble.tex` — the shared preamble for the agent-endpoint
defense paper. Compile the paper with `tectonic main.tex` (or pdflatex/latexmk).
This file documents what the preamble sets up; `preamble.tex` remains the source
of truth for the build.

## Page geometry & fonts

| Package | Setting | Purpose |
|---|---|---|
| `geometry` | A4, 0.75in margins, 0.28in column sep | page layout |
| `fontenc` | T1 | output font encoding |
| `inputenc` | utf8 | source encoding |
| `newtxtext,newtxmath` | — | Times-like text with matching math |
| `beramono` | scaled 0.85 | readable monospace for code/paths |
| `microtype` | — | better justification and protrusion |

## Math, units, numbers

- `amsmath` — math environments.
- `siunitx` — units and number formatting; `\sisetup` uses a comma group
  separator, groups at 4+ digits, and `detect-all` to match the surrounding font.

## Tables

- `booktabs`, `multirow`, `tabularx`, `makecell`.
- Row height: `\arraystretch` = 1.12.

## Figures & plots

- `graphicx`, `xcolor`.
- `tikz` with libraries: `arrows.meta`, `positioning`, `fit`, `backgrounds`,
  `shapes.geometric`.
- `pgfplots` (compat 1.18).
- `caption` (small, bold label, 4pt skip) and `subcaption`.

## Lists, code, misc

- `enumitem` — lists set to `nosep`, `leftmargin=*`.
- `listings` — code blocks: `\ttfamily\footnotesize`, full-flexible columns,
  line breaking, single frame (0.3pt, 30% black rule), tight margins/skips.
- `balance` — balance the columns on the last page.

## Colour palette

| Name | Hex | Role |
|---|---|---|
| `accent` | `#1F4E79` | section headings, findings, emphasis (deep blue) |
| `good` | `#2E7D32` | pass marks, positive results (green) |
| `bad` | `#B71C1C` | fail marks, placeholders, warnings (red) |
| `warn` | `#E65100` | caution / gate elements (orange) |
| `muted` | `#5F6368` | secondary labels (grey) |

## Section styling

- `titlesec`.
- Section titles: large, bold, `accent` colour, 0.6em gap after the number.
- Subsection titles: normal size, bold, 0.5em gap.
- Tight vertical spacing around both (`\titlespacing*`).

## Bibliography

- `natbib` with `numbers,sort&compress`; `\bibsep` = 2pt.

## Hyperlinks (loaded late)

- `hyperref` (`hidelinks`, `pdfusetitle`), `url`, `cleveref`
  (`capitalise`, `noabbrev`).

## Project macros

| Macro | Renders as | Meaning |
|---|---|---|
| `\sys` | Guardian (small caps) | the admission-gate system |
| `\bastion` | Bastion (small caps) | the post-auth content-defense module |
| `\mirage` | Mirage (small caps) | the v5 risk-adaptive routing extension |
| `\kit` | `agentkit` (mono) | the protected tool gateway |
| `\code{...}` | monospace, small | inline code, flags, paths |
| `\us` | thin space + µs | microseconds unit |
| `\ms` | thin space + ms | milliseconds unit |
| `\pass` | green ✓ | passing / positive result (needs `pifont`) |
| `\fail` | red ✗ | failing / negative result (needs `pifont`) |
| `\placeholder{...}` | red bold `[...]` | unmissable TODO — grep `\placeholder` before submitting |
| `\finding{...}` | accent-coloured bold run-in heading | starts a results/finding paragraph |

> Note: `pifont` (for `\pass`/`\fail`) is loaded alongside these macros.
