#!/usr/bin/env python3
"""Run Bastion's detector directly on the exact C10 / H1 / H9 stress payloads.

The stress suites (megaharness.py, megaharness_hard.py) send C10, H1 and H9
payloads to `shell_explain`, which Bastion exempts from injection checks by
default (BASTION_EXEMPT_TOOLS), and they record only the HTTP status. A Bastion
block is a JSON-RPC error inside HTTP 200. So the HTTP outcomes of those three
categories say nothing about Bastion's detector: the 403s there are Guardian
source bans.

This script reads the exact cases from the plan files, decodes each tool-call
argument, and runs it through bastion.check_input() as a NON-exempt tool
(`devops_ask`, the same call fp_corpus.py makes). The check is a deterministic
function, so each distinct payload is evaluated once and weighted by how many
times the plan sent it.

Run:  AT=~/agent-tools python3 stress_bastion_direct.py [out.json]
"""
from __future__ import annotations
import json, os, pathlib, sys
from collections import Counter, defaultdict

HERE = pathlib.Path(__file__).resolve().parent
AT = pathlib.Path(os.environ["AT"]).expanduser()
sys.path.insert(0, str(AT))
os.environ.setdefault("BASTION_INPUT_MODE", "block")
from agentkit import bastion  # noqa: E402

PLANS = {
    "C10_bastion": HERE / "megaharness_plan.jsonl",
    "H1_waf_bypass": HERE / "megaharness_hard_plan.jsonl",
    "H9_fp_stress": HERE / "megaharness_hard_plan.jsonl",
}
TOOL = "devops_ask"


def arg_text(case: dict) -> str | None:
    body = case.get("body")
    if not body:
        return None
    try:
        msg = json.loads(body)
    except Exception:
        return None
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return None
    args = (msg.get("params") or {}).get("arguments") or {}
    if not isinstance(args, dict):
        return None
    vals = [v for v in args.values() if isinstance(v, str)]
    return vals[0] if vals else None


def main() -> None:
    wanted = set(PLANS)
    # (category, subcategory) -> Counter(payload -> times sent)
    corpus: dict[tuple[str, str], Counter] = defaultdict(Counter)
    tool_used: dict[str, Counter] = defaultdict(Counter)
    for plan in sorted(set(PLANS.values())):
        cats = {c for c, p in PLANS.items() if p == plan}
        with open(plan) as f:
            for line in f:
                if not any(c in line for c in cats):
                    continue
                case = json.loads(line)
                cat = case.get("category")
                if cat not in wanted:
                    continue
                text = arg_text(case)
                if text is None:
                    continue
                try:
                    tool_used[cat][json.loads(case["body"])["params"]["name"]] += 1
                except Exception:
                    pass
                corpus[(cat, case.get("subcategory") or "")][text] += 1

    verdict: dict[str, str | None] = {}
    out: dict = {"tool_checked_as": TOOL, "tool_used_in_stress": {}, "categories": {}}
    for cat, c in tool_used.items():
        out["tool_used_in_stress"][cat] = dict(c)
        out["exempt_in_stress"] = sorted(bastion.config.BASTION_EXEMPT_TOOLS)

    for (cat, sub), payloads in sorted(corpus.items()):
        sent = sum(payloads.values())
        blocked = 0
        uniq_blocked = 0
        missed = []
        for p, n in payloads.items():
            if p not in verdict:
                verdict[p] = bastion.check_input(TOOL, {"message": p})
            if verdict[p]:
                blocked += n
                uniq_blocked += 1
            else:
                missed.append(p)
        out["categories"].setdefault(cat, {})[sub] = {
            "sent": sent, "blocked": blocked, "passed": sent - blocked,
            "distinct_payloads": len(payloads), "distinct_blocked": uniq_blocked,
            "passed_examples": [m[:120] for m in missed[:8]],
        }

    for cat, subs in out["categories"].items():
        s = sum(v["sent"] for v in subs.values())
        b = sum(v["blocked"] for v in subs.values())
        d = sum(v["distinct_payloads"] for v in subs.values())
        db = sum(v["distinct_blocked"] for v in subs.values())
        subs["_total"] = {"sent": s, "blocked": b, "passed": s - b,
                          "distinct_payloads": d, "distinct_blocked": db}

    dest = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "stress_bastion_direct.json"
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
