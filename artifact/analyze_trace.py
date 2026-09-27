"""Analyze a real Guardian access trace and replay it through three policies.

    python3 analyze_trace.py TRACE.jsonl [--since ISO] [--exclude-ua SUBSTR] [--out real_traffic.json]

1. Characterizes the traffic (volume, sources, user-agent classes, paths).
2. Replays every request, in timestamp order and on the trace's own clock,
   through: no defense, Guardian v1, and Guardian v2 — the same traffic judged
   by each policy. Each policy runs in its own subprocess against its own code
   tree with a throwaway state dir, so v1 and v2 never share state.

Output is aggregate-only: no IP addresses or raw user-agents are written, so the
JSON is safe to publish. (Keep the raw trace private.)
"""
from __future__ import annotations
import argparse, collections, datetime as dt, ipaddress, json, os, pathlib, re, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).parent
TREES = {"v1": pathlib.Path.home() / "agent-tools.bak-2026-09-26-guardian-v1",
         "v2": pathlib.Path.home() / "agent-tools"}

AI_CRAWLERS = ["gptbot", "oai-searchbot", "chatgpt-user", "ccbot", "claudebot", "claude-web",
               "anthropic-ai", "google-extended", "googleother", "applebot", "perplexity",
               "bytespider", "amazonbot", "meta-externalagent", "facebookbot", "cohere-ai",
               "diffbot", "youbot", "timpibot", "imagesiftbot", "omgili"]
SCANNERS = ["masscan", "zgrab", "nuclei", "sqlmap", "nikto", "wpscan", "dirbuster", "gobuster",
            "feroxbuster", "censys", "shodan", "internet-measurement", "expanse", "paloalto",
            "l9explore", "l9tcpid", "leakix", "netcraft", "zmap", "nmap", "odin", "modat",
            "fasthttp", "httpx - open-source", "projectdiscovery", "scaninfo", "criminalip", "onyphe"]
SEO_BOTS = ["semrush", "ahrefs", "mj12bot", "dotbot", "petalbot", "serpstat", "dataforseo",
            "bingbot", "googlebot", "yandex", "baiduspider", "duckduckbot", "slurp", "seznam"]
MCP_CLIENTS = ["claude-code", "claude", "mcp", "cursor", "openai-mcp", "windsurf", "cline", "anthropic"]
LIBS = ["curl", "wget", "python", "go-http-client", "okhttp", "axios", "node", "java", "libwww",
        "httpclient", "ruby", "php", "rust", "reqwest", "aiohttp", "undici", "postman"]


def ua_class(ua: str) -> str:
    u = (ua or "").lower()
    if not u:
        return "empty"
    for name, sigs in (("ai_crawler", AI_CRAWLERS), ("scanner", SCANNERS), ("seo_search_bot", SEO_BOTS),
                       ("mcp_client", MCP_CLIENTS)):
        if any(s in u for s in sigs):
            return name
    if any(s in u for s in LIBS):
        return "http_library"
    if "mozilla/" in u:
        return "browser_like"
    if re.search(r"bot|crawl|spider|scan", u):
        return "other_bot"
    return "other"


def path_class(method: str, path: str) -> str:
    p = (path or "").split("?")[0]
    if p.rstrip("/") == "/mcp":
        return "mcp_endpoint"
    if p in ("/", ""):
        return "root"
    if p.startswith("/.well-known/"):
        return "well_known"
    if p in ("/robots.txt", "/favicon.ico", "/sitemap.xml") or p.startswith("/apple-touch-icon"):
        return "crawler_meta"
    if p == "/healthz":
        return "health"
    return "other_probe"


def source(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if a.version == 6 else ip


# ── replay worker (runs inside a subprocess with one policy's code tree) ──────
WORKER = r'''
import json, os, sys
sys.path.insert(0, os.environ["TREE"])
from agentkit import guardian, config
clock = [0.0]
guardian._now = lambda: clock[0]
v2 = hasattr(guardian, "authfail_ban")
BENIGN_404 = ("/.well-known/", "/favicon.ico", "/apple-touch-icon")
recs = [json.loads(l) for l in open(os.environ["TRACE"])]
out = []
for r in recs:
    clock[0] = r["ts"]; ip, ua, m, p = r["ip"], r.get("ua", ""), r["method"], r["path"]
    auth = r.get("auth") or ("bad" if r["status"] == 401 else "ok")
    allowed, st, why = guardian.gate(ip, ua) if (v2 or m != "DELETE") else (True, 0, "")
    if not allowed:
        out.append([st, why.split(":")[0]]); continue
    path = p.split("?")[0]
    if m == "POST":
        if v2 and r.get("clen", 0) > 262144: out.append([413, "oversize"]); continue
        if path.rstrip("/") != "/mcp":
            note = ""
            if v2 and not p.startswith(BENIGN_404) and guardian.note_probe(ip):
                guardian.ban(ip, reason="probe_scan"); note = "probe_ban"
            out.append([404, note]); continue
        if auth != "ok":
            note = "authfail"
            if guardian.note_authfail(ip):
                (guardian.authfail_ban(ip) if v2 else guardian.ban(ip, reason="authfail_flood")); note = "authfail_ban"
            out.append([401, note]); continue
        out.append([r["status"] if r["status"] in (200, 202) else 200, "served"]); continue
    if m == "GET":
        if path == "/": out.append([200, "root"]); continue
        if v2 and path == "/robots.txt": out.append([200, "robots"]); continue
        if path.rstrip("/") == "/mcp" or not v2: out.append([405, ""]); continue
        note = ""
        if not p.startswith(BENIGN_404) and guardian.note_probe(ip):
            guardian.ban(ip, reason="probe_scan"); note = "probe_ban"
        out.append([404, note]); continue
    out.append([200, "other_method"])
print(json.dumps(out))
'''


def replay(tree: pathlib.Path, trace_file: str) -> list:
    with tempfile.TemporaryDirectory() as sd:
        r = subprocess.run([sys.executable, "-c", WORKER], capture_output=True, text=True,
                           env=dict(os.environ, TREE=str(tree), TRACE=trace_file, GUARDIAN_STATE_DIR=sd,
                                    PYTHONPATH=str(tree), GUARDIAN_LOG_MAX="1000000000"))
        if r.returncode:
            raise RuntimeError(r.stderr[-2000:])
        return json.loads(r.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--since", help="ISO datetime; drop earlier records")
    ap.add_argument("--exclude-ua", action="append", default=[], help="drop operator self-tests by UA substring")
    ap.add_argument("--out", default=str(HERE / "real_traffic.json"))
    a = ap.parse_args()

    recs = []
    for ln in open(a.trace):
        try:
            recs.append(json.loads(ln))
        except ValueError:
            continue
    if a.since:
        t0 = dt.datetime.fromisoformat(a.since).timestamp()
        recs = [r for r in recs if r["ts"] >= t0]
    recs = [r for r in recs if not any(x in (r.get("ua") or "") for x in a.exclude_ua)]
    recs.sort(key=lambda r: r["ts"])
    if not recs:
        sys.exit("no records")

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
        tf = f.name

    span_h = (recs[-1]["ts"] - recs[0]["ts"]) / 3600
    srcs = collections.Counter(source(r["ip"]) for r in recs)
    cls = collections.Counter(ua_class(r.get("ua")) for r in recs)
    cls_src = collections.defaultdict(set)
    for r in recs:
        cls_src[ua_class(r.get("ua"))].add(source(r["ip"]))
    paths = collections.Counter(path_class(r["method"], r["path"]) for r in recs)
    hours = collections.Counter(int((r["ts"] - recs[0]["ts"]) // 3600) for r in recs)
    first_contact_h = None
    ext = [r for r in recs if ua_class(r.get("ua")) != "mcp_client"]
    if ext:
        first_contact_h = round((ext[0]["ts"] - recs[0]["ts"]) / 3600, 2)
    auth = collections.Counter(r.get("auth", "?") for r in recs if r["method"] == "POST"
                               and path_class(r["method"], r["path"]) == "mcp_endpoint")
    per_src = sorted(srcs.values(), reverse=True)
    top10_share = round(sum(per_src[:10]) / len(recs), 3)

    res = {"window": {"start": dt.datetime.fromtimestamp(recs[0]["ts"]).isoformat(timespec="minutes"),
                      "end": dt.datetime.fromtimestamp(recs[-1]["ts"]).isoformat(timespec="minutes"),
                      "hours": round(span_h, 1)},
           "requests": len(recs), "sources": len(srcs),
           "ipv6_sources": sum(1 for s in srcs if ":" in s),
           "top10_source_share": top10_share,
           "max_requests_one_source": per_src[0],
           "ua_class_requests": dict(cls.most_common()),
           "ua_class_sources": {k: len(v) for k, v in sorted(cls_src.items(), key=lambda kv: -len(kv[1]))},
           "path_class": dict(paths.most_common()),
           "mcp_post_auth": dict(auth),
           "distinct_uas": len({r.get("ua") for r in recs}),
           "peak_hour_requests": max(hours.values()),
           "policies": {}}

    live = collections.Counter(r["status"] for r in recs)
    res["observed_status"] = {str(k): v for k, v in sorted(live.items())}

    def summarize(outcomes):
        st = collections.Counter(o[0] for o in outcomes)
        why = collections.Counter(o[1] for o in outcomes if o[1])
        reached_auth = sum(1 for o in outcomes if o[1] in ("served", "authfail", "authfail_ban"))
        blocked = sum(1 for o in outcomes if o[0] in (403, 429))
        unwanted = [i for i, r in enumerate(recs) if ua_class(r.get("ua")) != "mcp_client"]
        unwanted_blocked = sum(1 for i in unwanted if outcomes[i][0] in (403, 429))
        return {"status": {str(k): v for k, v in sorted(st.items())}, "reasons": dict(why.most_common()),
                "blocked_at_gate": blocked, "reached_auth": reached_auth,
                "non_mcp_client_requests": len(unwanted),
                "non_mcp_client_blocked_at_gate": unwanted_blocked}

    none = []
    for r in recs:
        p = path_class(r["method"], r["path"])
        if r["method"] == "POST" and p == "mcp_endpoint":
            none.append([200, "served"] if r.get("auth", "ok") == "ok" else [401, "authfail"])
        elif r["method"] == "GET" and p == "root":
            none.append([200, "root"])
        else:
            none.append([404 if r["method"] == "POST" else 405, ""])
    res["policies"]["none"] = summarize(none)
    for tag, tree in TREES.items():
        res["policies"][tag] = summarize(replay(tree, tf))
    os.unlink(tf)
    pathlib.Path(a.out).write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
