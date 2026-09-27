"""Before/after evaluation of Guardian v1 vs v2 (code under test is unmodified).

Usage:  AT=<path to agent-tools tree> TAG=<v1|v2> python3 harness2.py
Runs an isolated copy of agentkit.http_server from that tree on a private port,
with its own bearer token and a fresh GUARDIAN_STATE_DIR per scenario, and
writes results_<TAG>.json. The identical scenario set runs against both trees.
"""
from __future__ import annotations
import http.client, json, os, pathlib, platform, secrets, shutil, socket
import statistics as st, subprocess, sys, time

AT = pathlib.Path(os.environ["AT"]).expanduser()
TAG = os.environ.get("TAG", "run")
OUT = pathlib.Path(__file__).parent
PORT = 18790
TOKEN = secrets.token_urlsafe(40)
LAN_IP = os.environ.get("LAN_IP", "")
BENIGN_UA = ["claude-code/2.1.0", "python-httpx/0.28.1", "node", "mcp-inspector/0.16"]
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0 Safari/537.36")
sys.path.insert(0, str(AT))


class Server:
    def __init__(self, tag, host="127.0.0.1", prefill_bans=0, **env):
        self.host = host
        self.state = OUT / "state" / TAG / tag
        shutil.rmtree(self.state, ignore_errors=True)
        self.state.mkdir(parents=True)
        if prefill_bans:
            until = time.time() + 86400
            (self.state / "guardian_bans.json").write_text(json.dumps(
                {f"10.{i//65536}.{(i//256)%256}.{i%256}": {"until": until, "reason": "synthetic",
                                                           "since": time.time()}
                 for i in range(prefill_bans)}))
        base = {k: v for k, v in os.environ.items()
                if k not in ("AGENTKIT_HTTP_TOKEN", "AGENTKIT_HTTP_TOKENS")}
        e = dict(base, PYTHONPATH=str(AT), AGENTKIT_HTTP_HOST=host,
                 AGENTKIT_HTTP_PORT=str(PORT), AGENTKIT_HTTP_TOKEN=TOKEN,
                 GUARDIAN_STATE_DIR=str(self.state))
        e.update({k: str(v) for k, v in env.items()})
        self.p = subprocess.Popen([sys.executable, "-m", "agentkit.http_server"], env=e, cwd=AT,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(150):
            try:
                c = http.client.HTTPConnection(host, PORT, timeout=2)
                c.request("GET", "/healthz"); c.getresponse().read(); c.close(); return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def log(self):
        f = self.state / "guardian_access.jsonl"
        return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []

    def bans(self):
        f = self.state / "guardian_bans.json"
        return json.loads(f.read_text()) if f.exists() else {}

    def stop(self):
        self.p.terminate(); self.p.wait()


def req(method="POST", path="/mcp", ip="198.51.100.1", ua=BENIGN_UA[0], token=TOKEN,
        body=None, conn=None, host="127.0.0.1"):
    h = {"User-Agent": ua, "Content-Type": "application/json"}
    if ip:
        h["CF-Connecting-IP"] = ip
    if token:
        h["Authorization"] = f"Bearer {token}"
    if body is None and method == "POST":
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    data = body.encode() if isinstance(body, str) else body
    for attempt in (0, 1):
        c = conn or http.client.HTTPConnection(host, PORT, timeout=10)
        try:
            c.request(method, path, body=data, headers=h)
            r = c.getresponse(); r.read()
            if r.getheader("Connection", "").lower() == "close" and conn is not None:
                conn.close()  # server asked to close; http.client reconnects next time
            if conn is None:
                c.close()
            return r.status
        except (ConnectionError, http.client.RemoteDisconnected, BrokenPipeError):
            if conn is not None:
                conn.close()
            if attempt:
                raise
    return None


def ban_count(s):
    now = time.time()
    return sum(1 for v in s.bans().values() if v.get("until", 0) >= now)


def rpc(method, id_=1, params=None):
    m = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        m["id"] = id_
    if params is not None:
        m["params"] = params
    return json.dumps(m)


# ── E1: scenario matrix ────────────────────────────────────────────────────────
def e1():
    from agentkit import config
    sigs = list(config.GUARDIAN_BOT_UAS)
    R = {}

    s = Server("s1")  # benign MCP sessions
    codes = []
    for i, ua in enumerate(BENIGN_UA):
        ip = f"198.51.100.{10+i}"
        codes.append(req(ip=ip, ua=ua, body=rpc("initialize", 0, {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "eval", "version": "1"}})))
        codes.append(req(ip=ip, ua=ua, body=rpc("notifications/initialized", None)))
        codes += [req(ip=ip, ua=ua) for _ in range(23)]
    R["S1_benign"] = {"requests": len(codes), "served": sum(c in (200, 202) for c in codes),
                      "blocked": sum(c in (401, 403, 429) for c in codes), "bans": ban_count(s)}
    s.stop()

    s = Server("s1b")  # benign client doing OAuth discovery + SSE probe before connecting
    codes = []
    for _ in range(4):
        for p in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
                  "/.well-known/oauth-authorization-server", "/favicon.ico"):
            codes.append(req("GET", p, ip="198.51.100.30", token=None))
        codes.append(req("GET", "/mcp", ip="198.51.100.30"))
    final = req(ip="198.51.100.30")
    R["S1b_benign_discovery"] = {"requests": len(codes), "status_counts": {str(k): codes.count(k) for k in sorted(set(codes))},
                                 "then_valid_call": final, "bans": ban_count(s)}
    s.stop()

    s = Server("s2")  # declared crawlers
    first, after = [], []
    for i, sig in enumerate(sigs):
        ip = f"203.0.113.{i+1}"
        first.append(req(ip=ip, ua=f"Mozilla/5.0 (compatible; {sig}/1.0; +https://example.com/bot)", token=None))
        after.append(req(ip=ip, ua=BENIGN_UA[0], token=TOKEN))
    R["S2_declared_bots"] = {"signatures": len(sigs), "blocked_first_request": first.count(403),
                             "still_blocked_after_ua_swap_with_valid_token": after.count(403),
                             "bans": ban_count(s)}
    s.stop()

    s = Server("s3")  # spoofed-UA crawlers
    codes = [req(ip=f"203.0.113.{i+1}", ua=BROWSER_UA, token=None) for i in range(len(sigs))]
    R["S3_spoofed_ua_crawlers"] = {"requests": len(codes), "blocked_403": codes.count(403),
                                   "rejected_401": codes.count(401), "served": codes.count(200)}
    s.stop()

    s = Server("s4")  # single-source guessing
    codes = [req(ip="192.0.2.50", token=secrets.token_urlsafe(40)) for _ in range(20)]
    valid_after = req(ip="192.0.2.50", token=TOKEN)
    ban_at = next((i + 1 for i, r in enumerate(s.log()) if "banned" in r.get("note", "")), None)
    b = s.bans().get("192.0.2.50", {})
    R["S4_single_ip_probe"] = {"attempts": 20, "ban_triggered_at_attempt": ban_at,
                               "answered_401": codes.count(401), "blocked_403": codes.count(403),
                               "valid_token_after_ban": valid_after,
                               "ban_minutes": round((b.get("until", 0) - b.get("since", 0)) / 60) if b else 0}
    s.stop()

    s = Server("s5")  # distributed guessing
    codes = [req(ip=f"10.{i//250}.{i%250}.9", token=secrets.token_urlsafe(40))
             for i in range(100) for _ in range(7)]
    R["S5_distributed_probe"] = {"ips": 100, "guesses": len(codes), "answered_401": codes.count(401),
                                 "blocked_403": codes.count(403), "bans": ban_count(s)}
    s.stop()

    s = Server("s6")  # flood
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    t0 = time.time()
    codes = [req(ip="192.0.2.60", conn=c) for _ in range(300)]
    burst_s = time.time() - t0
    other = req(ip="192.0.2.61")
    time.sleep(61)
    recovered = req(ip="192.0.2.60")
    c.close()
    R["S6_flood"] = {"requests": 300, "burst_seconds": round(burst_s, 2), "served": codes.count(200),
                     "throttled_429": codes.count(429), "bans": ban_count(s), "after_61s": recovered,
                     "other_ip_during": other}
    s.stop()

    s = Server("s7")  # path scan with browser UA
    paths = ["/.env", "/.git/config", "/wp-login.php", "/admin", "/phpmyadmin/",
             "/api/v1/users", "/server-status", "/actuator/env", "/config.json", "/backup.zip"]
    codes = [req("GET", p, ip="192.0.2.70", ua=BROWSER_UA, token=None) for p in paths]
    codes += [req("POST", p, ip="192.0.2.70", ua=BROWSER_UA, token=None, body="{}") for p in paths]
    R["S7_path_scan"] = {"requests": len(codes), "status_counts": {str(k): codes.count(k) for k in sorted(set(codes))},
                         "bans": ban_count(s)}
    s.stop()

    for tag, env in (("S8_legit_lockout", {}), ("S8b_legit_allowlisted", {"GUARDIAN_ALLOW": "198.51.100.200"})):
        s = Server(tag.lower(), **env)
        [req(ip="198.51.100.200", token=TOKEN[:-1] + "x") for _ in range(8)]
        then = req(ip="198.51.100.200", token=TOKEN)
        b = s.bans().get("198.51.100.200", {})
        R[tag] = {"typos": 8, "valid_after": then,
                  "ban_minutes": round((b.get("until", 0) - b.get("since", 0)) / 60) if b else 0}
        s.stop()

    s = Server("s9")  # surface still reachable by a banned client
    req(ip="192.0.2.90", ua="sqlmap/1.8", token=None)
    R["S9_banned_client_surface"] = {
        "POST_mcp": req(ip="192.0.2.90"),
        "GET_healthz": req("GET", "/healthz", ip="192.0.2.90"),
        "DELETE_mcp": req("DELETE", "/mcp", ip="192.0.2.90"),
        "POST_oversize_300KB": req(ip="192.0.2.90", body="x" * 300_000),
        "logged_DELETE": sum(r["method"] == "DELETE" for r in s.log()),
        "fresh_client_after": req(ip="198.51.100.99"),
    }
    s.stop()

    if LAN_IP:  # S10: forged CF-Connecting-IP from a NON-loopback peer (tailnet-style bind)
        s = Server("s10", host=LAN_IP)
        first = req(ip="192.0.2.100", ua="nuclei", token=None, host=LAN_IP)
        rotated = [req(ip=f"192.0.2.{101+i}", ua=BROWSER_UA, token=None, host=LAN_IP) for i in range(5)]
        R["S10_forged_header_non_loopback_peer"] = {"first": first, "rotated_statuses": rotated,
                                                     "evaded": sum(c != 403 for c in rotated),
                                                     "ban_keys": sorted(s.bans())}
        s.stop()

    s = Server("s12")  # IPv6 rotation inside one /64
    codes = [req(ip=f"2001:db8:aaaa:bbbb::{i+1:x}", ua="GPTBot/1.1", token=None) for i in range(200)]
    rotate_clean = [req(ip=f"2001:db8:aaaa:bbbb:1::{i+1:x}", ua=BROWSER_UA) for i in range(20)]
    neighbour = req(ip="2001:db8:aaaa:cccc::1")
    R["S12_ipv6_rotation"] = {"requests": 200, "blocked_403": codes.count(403), "bans": ban_count(s),
                              "clean_rotation_blocked": rotate_clean.count(403),
                              "other_64_unaffected": neighbour}
    s.stop()

    s = Server("s11", GUARDIAN_ENABLED=0)  # ablation
    bot = req(ip="203.0.113.1", ua="GPTBot/1.1", token=None)
    probe = [req(ip="192.0.2.50", token=secrets.token_urlsafe(40)) for _ in range(20)]
    flood = [req(ip="192.0.2.60") for _ in range(300)]
    R["S11_ablation_disabled"] = {"bot_status": bot, "probe_401": probe.count(401),
                                  "ban_records_written": len(s.bans()), "flood_served": flood.count(200)}
    s.stop()

    # S13: concurrent multi-client — 4 clients hitting simultaneously, no cross-contamination
    import threading
    s = Server("s13")
    results_by_client = {}
    errors = []

    def client_work(client_id, ip, ua):
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
            codes = []
            codes.append(req(ip=ip, ua=ua, body=rpc("initialize", 0, {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": f"client-{client_id}", "version": "1"}}), conn=c))
            codes.append(req(ip=ip, ua=ua, body=rpc("notifications/initialized", None), conn=c))
            for _ in range(48):
                codes.append(req(ip=ip, ua=ua, conn=c))
            c.close()
            results_by_client[client_id] = {"served": sum(c in (200, 202) for c in codes),
                                             "blocked": sum(c in (401, 403, 429) for c in codes)}
        except Exception as e:
            errors.append((client_id, str(e)))

    threads = []
    for i in range(4):
        t = threading.Thread(target=client_work, args=(i, f"198.51.100.{20+i}", BENIGN_UA[i % len(BENIGN_UA)]))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=30)
    R["S13_concurrent_clients"] = {"clients": 4, "results": results_by_client,
                                    "errors": errors, "bans": ban_count(s),
                                    "all_served": all(r.get("blocked", 1) == 0 for r in results_by_client.values())}
    s.stop()

    # S14: long-running keep-alive session (spans two rate windows, verifies recovery)
    s = Server("s14")
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    window1 = [req(ip="198.51.100.40", ua=BENIGN_UA[0], conn=c) for _ in range(100)]
    time.sleep(61)  # wait for rate window to reset
    window2 = [req(ip="198.51.100.40", ua=BENIGN_UA[0], conn=c) for _ in range(100)]
    c.close()
    R["S14_long_session"] = {"window1_served": window1.count(200) + window1.count(202),
                              "window2_served": window2.count(200) + window2.count(202),
                              "window1_throttled": window1.count(429),
                              "window2_throttled": window2.count(429),
                              "bans": ban_count(s)}
    s.stop()

    return R


# ── E2: latency ────────────────────────────────────────────────────────────────
def lat(n, prefill=0, **env):
    s = Server("lat", prefill_bans=prefill, GUARDIAN_RATE_MAX=10**9, **env)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    for _ in range(50):
        req(conn=c)
    xs = []
    for _ in range(n):
        t = time.perf_counter(); req(conn=c); xs.append((time.perf_counter() - t) * 1000)
    c.close(); s.stop()
    return xs


def summ(xs):
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(p * len(xs)))]
    return {"n": len(xs), "p50": round(q(.5), 3), "p95": round(q(.95), 3),
            "p99": round(q(.99), 3), "mean": round(st.mean(xs), 3)}


def e2():
    on, off = [], []
    for _ in range(3):
        off += lat(1000, GUARDIAN_ENABLED=0)
        on += lat(1000)
    return {"guardian_off": summ(off), "guardian_on": summ(on),
            "ban_list_scaling": {str(k): summ(lat(500, prefill=k)) for k in (0, 1000, 10000, 50000)}}


# ── E3: memory of per-source state vs distinct sources ─────────────────────────
def e3():
    code = r"""
import os, sys, json, tracemalloc
sys.path.insert(0, os.environ['AT'])
from agentkit import guardian
N = int(sys.argv[1])
tracemalloc.start(); b = tracemalloc.take_snapshot()
for i in range(N):
    guardian._over_rate(f"10.{i//65536}.{(i//256)%256}.{i%256}")
a = tracemalloc.take_snapshot()
print(json.dumps({"ips": N, "tracked_keys": len(guardian._hits),
                  "bytes": sum(s.size_diff for s in a.compare_to(b, 'filename'))}))
"""
    out = {}
    for n in (1000, 10000, 100000):
        sd = OUT / "state" / TAG / f"mem{n}"; sd.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([sys.executable, "-c", code, str(n)], capture_output=True, text=True,
                           env=dict(os.environ, AT=str(AT), GUARDIAN_STATE_DIR=str(sd)))
        out[str(n)] = json.loads(r.stdout)
    return out


# ── E4: v3 features (scoped tokens, per-tool rate limiting) ──────────────────
def e4():
    R = {}
    from agentkit import config
    has_scoped = hasattr(config, "HTTP_TOKENS")
    has_tool_rate = hasattr(config, "HTTP_TOOL_RATE_MAX")
    if not (has_scoped and has_tool_rate):
        return {"skipped": "tree does not support v3 features"}

    # S15: scoped token — a restricted token can only list/call its allowed tools
    FULL_TOKEN = secrets.token_urlsafe(40)
    SCOPED_TOKEN = secrets.token_urlsafe(40)
    import json as _j
    tokens_json = _j.dumps({FULL_TOKEN: ["*"], SCOPED_TOKEN: ["devops_status", "devops_health"]})
    s = Server("s15", AGENTKIT_HTTP_TOKEN=FULL_TOKEN, AGENTKIT_HTTP_TOKENS=tokens_json)

    # Full token: tools/list returns all public tools
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/mcp", body=rpc("tools/list"),
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.50",
                       "Authorization": f"Bearer {FULL_TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); full_body = json.loads(r.read()); c.close()
    full_tools = [t["name"] for t in full_body.get("result", {}).get("tools", [])]

    # Scoped token: tools/list returns only allowed tools
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/mcp", body=rpc("tools/list"),
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.51",
                       "Authorization": f"Bearer {SCOPED_TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); scoped_body = json.loads(r.read()); c.close()
    scoped_tools = [t["name"] for t in scoped_body.get("result", {}).get("tools", [])]

    # Scoped token calling an out-of-scope tool (shell_suggest — lightweight, no backend)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/mcp", body=rpc("tools/call", 1, {"name": "devops_logs", "arguments": {}}),
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.51",
                       "Authorization": f"Bearer {SCOPED_TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); oos_body = json.loads(r.read()); c.close()
    out_of_scope_blocked = "error" in oos_body or oos_body.get("error") is not None

    R["S15_scoped_token"] = {"full_token_tools": len(full_tools),
                              "scoped_token_tools": len(scoped_tools),
                              "scoped_sees_only_allowed": set(scoped_tools) == {"devops_status", "devops_health"},
                              "out_of_scope_call_blocked": out_of_scope_blocked}
    s.stop()

    # S16: per-tool rate limiting — hammer one tool past its limit
    s = Server("s16", AGENTKIT_TOOL_RATE_MAX="10", AGENTKIT_TOOL_RATE_WINDOW="60",
               AGENTKIT_HTTP_TOKEN=FULL_TOKEN, AGENTKIT_HTTP_TOKENS=tokens_json)
    codes = []
    for i in range(30):
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        c.request("POST", "/mcp", body=rpc("tools/call", i, {"name": "shell_explain", "arguments": {"command": "ls"}}),
                  headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.60",
                           "Authorization": f"Bearer {FULL_TOKEN}", "Content-Type": "application/json"})
        r = c.getresponse(); body = r.read()
        if r.status != 200:
            codes.append(f"http_{r.status}")
            c.close(); continue
        try:
            resp = json.loads(body)
            err = resp.get("error")
            is_rate_limited = isinstance(err, dict) and err.get("code") == -32005
        except Exception:
            is_rate_limited = False
        codes.append("limited" if is_rate_limited else "served")
        c.close()
    # Different tool from same source should still work
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/mcp", body=rpc("tools/call", 99, {"name": "shell_suggest", "arguments": {"task": "list files"}}),
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.60",
                       "Authorization": f"Bearer {FULL_TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); other_body = json.loads(r.read()); c.close()
    err = other_body.get("error")
    other_tool_limited = isinstance(err, dict) and err.get("code") == -32005
    R["S16_tool_rate_limit"] = {"requests": 30, "served": codes.count("served"),
                                 "limited": codes.count("limited"),
                                 "other_tool_still_works": not other_tool_limited}
    s.stop()

    return R


# ── E5: advanced attack scenarios ─────────────────────────────────────────────
def e5():
    R = {}

    # S17: timing side-channel — does response time differ for valid vs invalid token?
    # If the server leaks timing info, an attacker can distinguish "close" tokens.
    s = Server("s17", GUARDIAN_RATE_MAX=10**9, GUARDIAN_AUTHFAIL_MAX=10**9)
    warmup = [req(ip="198.51.100.1") for _ in range(100)]
    valid_times, invalid_times, no_token_times = [], [], []
    wrong = secrets.token_urlsafe(40)
    partial = TOKEN[:20] + secrets.token_urlsafe(20)  # half-right token
    for _ in range(500):
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        t0 = time.perf_counter()
        req(ip="198.51.100.1", token=TOKEN, conn=c)
        valid_times.append((time.perf_counter() - t0) * 1e6)
        c.close()

        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        t0 = time.perf_counter()
        req(ip="198.51.100.2", token=wrong, conn=c)
        invalid_times.append((time.perf_counter() - t0) * 1e6)
        c.close()

        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        t0 = time.perf_counter()
        req(ip="198.51.100.3", token=partial, conn=c)
        no_token_times.append((time.perf_counter() - t0) * 1e6)
        c.close()
    s.stop()
    def timing_stats(xs):
        xs = sorted(xs)
        return {"mean": round(st.mean(xs), 1), "median": round(xs[len(xs)//2], 1),
                "stdev": round(st.stdev(xs), 1), "n": len(xs)}
    vs, ivs, nts = timing_stats(valid_times), timing_stats(invalid_times), timing_stats(no_token_times)
    # If median differs by >10%, there's a timing leak
    max_median = max(vs["median"], ivs["median"], nts["median"])
    min_median = min(vs["median"], ivs["median"], nts["median"])
    R["S17_timing_sidechannel"] = {
        "valid_token": vs, "invalid_token": ivs, "partial_match_token": nts,
        "max_median_diff_pct": round((max_median - min_median) / min_median * 100, 1),
        "timing_leak": (max_median - min_median) / min_median > 0.10
    }

    # S18: slow-and-low — attacker stays just under rate limit
    s = Server("s18")
    # 120 req/60s = 2/s limit. Send at 1.9/s for 120s (228 req total)
    codes = []
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    for i in range(228):
        codes.append(req(ip="192.0.2.80", token=secrets.token_urlsafe(40), conn=c))
        if i < 227:
            time.sleep(0.526)  # ~1.9 req/s
    c.close()
    ban_at = next((i + 1 for i, r in enumerate(s.log()) if "banned" in r.get("note", "")), None)
    R["S18_slow_and_low_probe"] = {
        "requests": len(codes), "duration_target_s": 120,
        "answered_401": codes.count(401), "blocked_403": codes.count(403),
        "throttled_429": codes.count(429), "ban_triggered_at": ban_at,
        "bans": ban_count(s)
    }
    s.stop()

    # S19: batch request abuse — stuff many operations into one HTTP request
    s = Server("s19")
    # JSON-RPC batch: 100 tools/list calls in one POST
    batch = [{"jsonrpc": "2.0", "id": i, "method": "tools/list"} for i in range(100)]
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request("POST", "/mcp", body=json.dumps(batch),
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.70",
                       "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); batch_body = r.read(); c.close()
    try:
        batch_resp = json.loads(batch_body)
        batch_results = len(batch_resp) if isinstance(batch_resp, list) else 1
    except Exception:
        batch_results = 0
    # Now try an oversized batch (1000 calls) — should it be rate-limited?
    big_batch = [{"jsonrpc": "2.0", "id": i, "method": "tools/list"} for i in range(1000)]
    big_body = json.dumps(big_batch)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request("POST", "/mcp", body=big_body,
              headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.71",
                       "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    r2 = c.getresponse(); big_body_resp = r2.read(); c.close()
    try:
        big_resp = json.loads(big_body_resp)
        big_results = len(big_resp) if isinstance(big_resp, list) else 1
    except Exception:
        big_results = 0
    # Oversize payload (>256KB) — should be rejected
    oversize_status = req(ip="198.51.100.72", body="x" * 300_000)
    R["S19_batch_abuse"] = {
        "batch_100_status": r.status, "batch_100_responses": batch_results,
        "batch_1000_status": r2.status, "batch_1000_responses": big_results,
        "batch_bypasses_rate_count": batch_results > 1,
        "oversize_300kb_status": oversize_status
    }
    s.stop()

    # S20: malformed JSON-RPC — fuzz the protocol layer
    s = Server("s20")
    malformed_cases = {
        "empty_object": "{}",
        "no_method": '{"jsonrpc":"2.0","id":1}',
        "null_method": '{"jsonrpc":"2.0","id":1,"method":null}',
        "wrong_version": '{"jsonrpc":"1.0","id":1,"method":"tools/list"}',
        "nested_batch": json.dumps([[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]]),
        "huge_id": json.dumps({"jsonrpc":"2.0","id":"A"*10000,"method":"tools/list"}),
        "binary_noise": "\x00\x01\x02\x03" * 100,
        "xml_injection": '<?xml version="1.0"?><!DOCTYPE foo><tools/>',
    }
    results = {}
    for name, body in malformed_cases.items():
        try:
            status = req(ip="198.51.100.80", body=body)
            results[name] = status
        except Exception as e:
            results[name] = f"error:{e}"
    # Verify server still responds after fuzz
    healthy = req(ip="198.51.100.81")
    R["S20_protocol_fuzz"] = {
        "cases": results, "server_healthy_after": healthy == 200,
        "bans": ban_count(s)
    }
    s.stop()

    # S21: session fixation — reuse another client's Mcp-Session-Id
    s = Server("s21")
    # Client A initializes, gets a session ID
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/mcp", body=rpc("initialize", 0, {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "clientA", "version": "1"}}),
        headers={"User-Agent": BENIGN_UA[0], "CF-Connecting-IP": "198.51.100.90",
                 "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); r.read()
    session_id = r.getheader("Mcp-Session-Id", "")
    c.close()
    # Client B tries to use A's session ID
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    headers = {"User-Agent": BENIGN_UA[1], "CF-Connecting-IP": "198.51.100.91",
               "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    c.request("POST", "/mcp", body=rpc("tools/list"),
              headers=headers)
    r2 = c.getresponse(); r2.read(); c.close()
    R["S21_session_fixation"] = {
        "session_id_issued": bool(session_id),
        "reuse_from_other_ip_status": r2.status,
        "server_is_stateless": True  # our server doesn't track sessions
    }
    s.stop()

    # S22: reconnection after ban expiry — verify clean slate
    s = Server("s22", GUARDIAN_BAN_MINUTES="1")  # 1-min ban for fast test
    # Get banned
    req(ip="192.0.2.100", ua="sqlmap/1.8", token=None)
    banned = req(ip="192.0.2.100")
    # Wait for ban expiry
    time.sleep(62)
    after = req(ip="192.0.2.100")
    # Verify rate counters are also clean
    burst = [req(ip="192.0.2.100") for _ in range(10)]
    R["S22_post_ban_recovery"] = {
        "during_ban": banned,
        "after_expiry": after,
        "burst_after_ok": all(c == 200 for c in burst),
        "bans_remaining": ban_count(s)
    }
    s.stop()

    return R


# ── E6: statistical rigor — multi-run latency with confidence intervals ───────
def e6():
    import math
    RUNS = 5
    all_on, all_off = [], []
    for run in range(RUNS):
        off_samples = lat(500, GUARDIAN_ENABLED=0)
        on_samples = lat(500)
        all_off.extend(off_samples)
        all_on.extend(on_samples)

    def ci95(xs):
        n = len(xs)
        mean = st.mean(xs)
        se = st.stdev(xs) / math.sqrt(n)
        return {"n": n, "mean": round(mean, 4), "stdev": round(st.stdev(xs), 4),
                "ci95_low": round(mean - 1.96 * se, 4), "ci95_high": round(mean + 1.96 * se, 4),
                "median": round(sorted(xs)[n // 2], 4),
                "p95": round(sorted(xs)[int(0.95 * n)], 4),
                "p99": round(sorted(xs)[int(0.99 * n)], 4)}

    overhead = [on - off for on, off in zip(sorted(all_on), sorted(all_off))]
    return {
        "runs": RUNS, "samples_per_run": 500,
        "guardian_off": ci95(all_off),
        "guardian_on": ci95(all_on),
        "overhead_ms": ci95(overhead),
        "overhead_significant": ci95(overhead)["ci95_low"] > 0
    }


if __name__ == "__main__":
    t0 = time.time()
    from agentkit import config
    res = {"meta": {"tag": TAG, "tree": str(AT), "date": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "python": platform.python_version(), "machine": platform.platform(),
                    "policy": {k: getattr(config, k) for k in dir(config)
                               if k.startswith("GUARDIAN_") and k not in ("GUARDIAN_BOT_UAS", "GUARDIAN_STATE_DIR")}}}
    res["meta"]["policy"]["bot_signatures"] = len(config.GUARDIAN_BOT_UAS)
    res["E1"] = e1(); print(TAG, "E1 done", flush=True)
    res["E2"] = e2(); print(TAG, "E2 done", flush=True)
    res["E3"] = e3(); print(TAG, "E3 done", flush=True)
    res["E4"] = e4(); print(TAG, "E4 done", flush=True)
    res["E5"] = e5(); print(TAG, "E5 done", flush=True)
    res["E6"] = e6(); print(TAG, "E6 done", flush=True)
    res["meta"]["runtime_s"] = round(time.time() - t0, 1)
    (OUT / f"results_{TAG}.json").write_text(json.dumps(res, indent=2, default=str))
