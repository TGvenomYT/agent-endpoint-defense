"""Reproducible evaluation of agentkit Guardian (unmodified code under test).

Runs an isolated copy of agentkit.http_server on a private port, with its own
bearer token and a throwaway GUARDIAN_STATE_DIR, and replays attack + benign
scenarios. Every number in the paper comes from results.json written here.
"""
from __future__ import annotations
import http.client, json, os, pathlib, secrets, shutil, statistics as st
import subprocess, sys, time, tracemalloc, platform

AGENT_TOOLS = pathlib.Path.home() / "agent-tools"
OUT = pathlib.Path(__file__).parent
PORT = 18790
TOKEN = secrets.token_urlsafe(40)
BENIGN_UA = ["claude-code/2.1.0", "python-httpx/0.28.1", "node", "mcp-inspector/0.16"]
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0 Safari/537.36")
sys.path.insert(0, str(AGENT_TOOLS))


class Server:
    def __init__(self, tag, **env):
        self.state = OUT / "state" / tag
        shutil.rmtree(self.state, ignore_errors=True)
        self.state.mkdir(parents=True)
        e = dict(os.environ, PYTHONPATH=str(AGENT_TOOLS), AGENTKIT_HTTP_HOST="127.0.0.1",
                 AGENTKIT_HTTP_PORT=str(PORT), AGENTKIT_HTTP_TOKEN=TOKEN,
                 GUARDIAN_STATE_DIR=str(self.state))
        e.update({k: str(v) for k, v in env.items()})
        self.p = subprocess.Popen([sys.executable, "-m", "agentkit.http_server"], env=e,
                                  cwd=AGENT_TOOLS, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
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
        body=None, conn=None):
    h = {"User-Agent": ua, "CF-Connecting-IP": ip, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if body is None and method == "POST":
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    data = body.encode() if isinstance(body, str) else body
    c = conn or http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); r.read()
    if conn is None:
        c.close()
    return r.status


def bot_sigs():
    from agentkit import config
    return list(config.GUARDIAN_BOT_UAS)


# ── E1: scenario matrix ────────────────────────────────────────────────────────
def e1():
    R = {}
    sigs = bot_sigs()

    # S1 benign MCP sessions from 4 client UAs, 4 distinct IPs, 25 calls each
    s = Server("s1")
    codes = []
    for i, ua in enumerate(BENIGN_UA):
        ip = f"198.51.100.{10+i}"
        codes.append(req(ip=ip, ua=ua, body=json.dumps(
            {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "eval", "version": "1"}}})))
        codes.append(req(ip=ip, ua=ua, body=json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"})))
        codes += [req(ip=ip, ua=ua) for _ in range(23)]
    R["S1_benign"] = {"requests": len(codes),
                      "served": sum(c in (200, 202) for c in codes),
                      "blocked": sum(c in (401, 403, 429) for c in codes),
                      "bans": len(s.bans())}
    s.stop()

    # S2 declared AI crawler / scanner UAs, one fresh IP each
    s = Server("s2")
    first, after = [], []
    for i, sig in enumerate(sigs):
        ip = f"203.0.113.{i+1}"
        ua = f"Mozilla/5.0 (compatible; {sig}/1.0; +https://example.com/bot)"
        first.append(req(ip=ip, ua=ua, token=None))
        after.append(req(ip=ip, ua=BENIGN_UA[0], token=TOKEN))  # UA swap + VALID token
    R["S2_declared_bots"] = {"signatures": len(sigs),
                             "blocked_first_request": sum(c == 403 for c in first),
                             "still_blocked_after_ua_swap_with_valid_token": sum(c == 403 for c in after),
                             "bans": len(s.bans())}
    s.stop()

    # S3 same crawlers with a spoofed browser UA and no token (UA rule evaded)
    s = Server("s3")
    codes = [req(ip=f"203.0.113.{i+1}", ua=BROWSER_UA, token=None) for i in range(len(sigs))]
    R["S3_spoofed_ua_crawlers"] = {"requests": len(codes),
                                   "blocked_by_ua_rule": sum(c == 403 for c in codes),
                                   "rejected_by_auth_401": sum(c == 401 for c in codes),
                                   "served": sum(c == 200 for c in codes)}
    s.stop()

    # S4 single-IP credential probing: 20 wrong tokens, then the valid one
    s = Server("s4")
    codes = [req(ip="192.0.2.50", token=secrets.token_urlsafe(40)) for _ in range(20)]
    valid_after = req(ip="192.0.2.50", token=TOKEN)
    ban_at = next((i + 1 for i, r in enumerate(s.log()) if "banned" in r.get("note", "")), None)
    R["S4_single_ip_probe"] = {"attempts": 20, "ban_triggered_at_attempt": ban_at,
                               "codes_401": codes.count(401), "codes_403": codes.count(403),
                               "valid_token_after_ban": valid_after}
    s.stop()

    # S5 distributed probing: 100 IPs x 7 guesses (just under AUTHFAIL_MAX=8)
    s = Server("s5")
    codes = [req(ip=f"10.{i//250}.{i%250}.9", token=secrets.token_urlsafe(40))
             for i in range(100) for _ in range(7)]
    R["S5_distributed_probe"] = {"ips": 100, "guesses": len(codes),
                                 "codes_401": codes.count(401), "bans": len(s.bans()),
                                 "token_bits": 40 * 8}
    s.stop()

    # S6 request flood: 300 back-to-back valid requests, one IP; then recovery after window
    s = Server("s6")
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    t0 = time.time()
    codes = [req(ip="192.0.2.60", conn=c) for _ in range(300)]
    burst_s = time.time() - t0
    time.sleep(61)
    recovered = req(ip="192.0.2.60", conn=c)
    other_ip = req(ip="192.0.2.61", conn=c)
    c.close()
    R["S6_flood"] = {"requests": 300, "burst_seconds": round(burst_s, 2),
                     "served": codes.count(200), "throttled_429": codes.count(429),
                     "bans": len(s.bans()), "after_61s": recovered,
                     "unaffected_other_ip_during": other_ip}
    s.stop()

    # S7 path / vulnerability scanning with a browser UA (no scanner signature)
    s = Server("s7")
    paths = ["/.env", "/.git/config", "/wp-login.php", "/admin", "/phpmyadmin/",
             "/api/v1/users", "/server-status", "/actuator/env", "/config.json", "/backup.zip"]
    codes = [req("GET", p, ip="192.0.2.70", ua=BROWSER_UA, token=None) for p in paths]
    codes += [req("POST", p, ip="192.0.2.70", ua=BROWSER_UA, token=None, body="{}") for p in paths]
    R["S7_path_scan"] = {"requests": len(codes), "status_counts": {str(k): codes.count(k) for k in set(codes)},
                         "bans": len(s.bans())}
    s.stop()

    # S8 legitimate-user lockout: a real user mistypes the token 8x, then gets it right
    s = Server("s8")
    typos = [req(ip="198.51.100.200", ua=BENIGN_UA[0], token=TOKEN[:-1] + "x") for _ in range(8)]
    then = req(ip="198.51.100.200", ua=BENIGN_UA[0], token=TOKEN)
    ban = s.bans().get("198.51.100.200", {})
    R["S8_legit_lockout"] = {"typos": 8, "valid_after": then,
                             "ban_minutes": round((ban.get("until", 0) - ban.get("since", 0)) / 60) if ban else 0}
    s.stop()

    # S9 gate-bypass surface for a BANNED client
    s = Server("s9")
    req(ip="192.0.2.90", ua="sqlmap/1.8", token=None)  # gets banned
    big = "x" * 300_000
    R["S9_banned_client_surface"] = {
        "POST_mcp": req(ip="192.0.2.90"),
        "GET_healthz": req("GET", "/healthz", ip="192.0.2.90"),
        "DELETE_mcp": req("DELETE", "/mcp", ip="192.0.2.90", body=None),
        "POST_oversize_300KB": req(ip="192.0.2.90", body=big),
        "logged_DELETE": sum(r["method"] == "DELETE" for r in s.log()),
    }
    s.stop()

    # S10 header trust: forged CF-Connecting-IP rotation by a banned client on the origin
    s = Server("s10")
    req(ip="192.0.2.100", ua="nuclei", token=None)
    rotated = [req(ip=f"192.0.2.{101+i}", ua=BROWSER_UA, token=None) for i in range(5)]
    R["S10_forged_client_ip_at_origin"] = {"banned_ip_status": req(ip="192.0.2.100", token=None),
                                           "rotated_statuses": rotated}
    s.stop()

    # S11 guardian disabled baseline for the same abuse (ablation)
    s = Server("s11", GUARDIAN_ENABLED=0)
    bot = req(ip="203.0.113.1", ua="GPTBot/1.1", token=None)
    probe = [req(ip="192.0.2.50", token=secrets.token_urlsafe(40)) for _ in range(20)]
    flood = [req(ip="192.0.2.60") for _ in range(300)]
    R["S11_ablation_disabled"] = {"bot_status": bot, "probe_401": probe.count(401),
                                  "probe_banned": len(s.bans()), "flood_served": flood.count(200),
                                  "logged": len(s.log())}
    s.stop()
    return R


# ── E2: latency overhead (end-to-end, keep-alive, loopback) ────────────────────
def lat(n, **env):
    s = Server("lat", GUARDIAN_RATE_MAX=10**9, **env)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    for _ in range(100):
        req(conn=c)  # warm-up
    xs = []
    for _ in range(n):
        t = time.perf_counter(); req(conn=c); xs.append((time.perf_counter() - t) * 1000)
    c.close(); s.stop()
    return xs


def lat_with_bans(n, nbans):
    s = Server("latb", GUARDIAN_RATE_MAX=10**9)
    s.stop()
    until = time.time() + 86400
    (s.state / "guardian_bans.json").write_text(json.dumps(
        {f"10.{i//65536}.{(i//256)%256}.{i%256}": {"until": until, "reason": "synthetic", "since": time.time()}
         for i in range(nbans)}))
    s2 = Server.__new__(Server); s2.state = s.state
    e = dict(os.environ, PYTHONPATH=str(AGENT_TOOLS), AGENTKIT_HTTP_HOST="127.0.0.1",
             AGENTKIT_HTTP_PORT=str(PORT), AGENTKIT_HTTP_TOKEN=TOKEN,
             GUARDIAN_STATE_DIR=str(s.state), GUARDIAN_RATE_MAX=str(10**9))
    s2.p = subprocess.Popen([sys.executable, "-m", "agentkit.http_server"], env=e, cwd=AGENT_TOOLS,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    for _ in range(20):
        req(conn=c)
    xs = []
    for _ in range(n):
        t = time.perf_counter(); req(conn=c); xs.append((time.perf_counter() - t) * 1000)
    c.close(); s2.stop()
    return xs


def summ(xs):
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(p * len(xs)))]
    return {"n": len(xs), "p50": round(q(.5), 3), "p95": round(q(.95), 3),
            "p99": round(q(.99), 3), "mean": round(st.mean(xs), 3)}


def e2():
    R = {}
    on, off = [], []
    for _ in range(3):  # interleave rounds to cancel drift
        off += lat(1000, GUARDIAN_ENABLED=0)
        on += lat(1000)
    R["guardian_off"], R["guardian_on"] = summ(off), summ(on)
    R["ban_list_scaling"] = {str(k): summ(lat_with_bans(500, k)) for k in (0, 1000, 10000, 50000)}
    return R


# ── E3: in-process memory of rate-limit state vs distinct client IPs ───────────
def e3():
    code = r"""
import os, sys, json, tracemalloc, time
sys.path.insert(0, os.environ['AT'])
os.environ['GUARDIAN_STATE_DIR'] = os.environ['SD']
from agentkit import guardian
N = int(sys.argv[1])
tracemalloc.start()
b = tracemalloc.take_snapshot()
for i in range(N):
    guardian._over_rate(f"10.{i//65536}.{(i//256)%256}.{i%256}")
time.sleep(0)
a = tracemalloc.take_snapshot()
d = sum(s.size_diff for s in a.compare_to(b, 'filename'))
print(json.dumps({"ips": N, "tracked_keys": len(guardian._hits), "bytes": d}))
"""
    out = {}
    for n in (1000, 10000, 100000):
        sd = OUT / "state" / f"mem{n}"; sd.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([sys.executable, "-c", code, str(n)], capture_output=True, text=True,
                           env=dict(os.environ, AT=str(AGENT_TOOLS), SD=str(sd)))
        out[str(n)] = json.loads(r.stdout)
    return out


if __name__ == "__main__":
    t0 = time.time()
    res = {"meta": {"date": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "python": platform.python_version(),
                    "machine": platform.platform(), "cpu": platform.processor()}}
    from agentkit import config
    res["meta"]["policy"] = {"rate_max": config.GUARDIAN_RATE_MAX, "rate_window": config.GUARDIAN_RATE_WINDOW,
                             "authfail_max": config.GUARDIAN_AUTHFAIL_MAX,
                             "authfail_window": config.GUARDIAN_AUTHFAIL_WINDOW,
                             "ban_minutes": config.GUARDIAN_BAN_MINUTES,
                             "bot_signatures": len(config.GUARDIAN_BOT_UAS)}
    res["E1"] = e1(); print("E1 done", flush=True)
    res["E2"] = e2(); print("E2 done", flush=True)
    res["E3"] = e3(); print("E3 done", flush=True)
    res["meta"]["runtime_s"] = round(time.time() - t0, 1)
    (OUT / "results.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
