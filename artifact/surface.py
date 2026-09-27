import json, sys
sys.path.insert(0, '.')
from harness import Server, req, PORT, TOKEN
import http.client
from agentkit import registry
s = Server("surface")
def call(body):
    c = http.client.HTTPConnection("127.0.0.1", PORT); c.request("POST", "/mcp", body=json.dumps(body),
        headers={"Authorization": f"Bearer {TOKEN}", "CF-Connecting-IP": "198.51.100.5", "Content-Type": "application/json"})
    r = c.getresponse(); d = json.loads(r.read()); c.close(); return d
listed = [t["name"] for t in call({"jsonrpc":"2.0","id":1,"method":"tools/list"})["result"]["tools"]]
lo = sorted(registry.local_only_names())
calls = {n: call({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":n,"arguments":{}}}).get("error",{}).get("code") for n in lo}
s.stop()
out = {"registry_total": len(registry.all_tools()) if hasattr(registry,'all_tools') else None, "http_listed": len(listed),
       "local_only": len(lo), "local_only_leaked_in_list": sorted(set(lo)&set(listed)),
       "local_only_call_error_codes": calls}
print(json.dumps(out, indent=1)); json.dump(out, open("surface.json","w"), indent=1)
