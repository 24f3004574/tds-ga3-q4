import json, os
os.environ.update(AI_API_KEY="k", AI_MODEL="fake", AI_BASE_URL="http://x/v1")
import httpx
from incident import planner

calls = []
class R:
    def __init__(self, code, body): self.status_code, self._b = code, body
    def raise_for_status(self):
        if self.status_code >= 400: raise httpx.HTTPStatusError("e", request=None, response=None)
    def json(self): return {"choices": [{"message": {"content": self._b}}]}

GOOD = {"rootCause": "capacity", "evidence": ["ev_001", "ev_002"],
        "diagnostics": [{"toolName": "query_metrics", "arguments": {}, "evidence": ["ev_001"]},
                        {"toolName": "query_metrics", "arguments": {"window": "5m"}, "evidence": ["ev_002"]}],
        "effectTool": "page_owner", "effectArguments": {}}
req = {
  "incident": {"incidentId": "i", "title": "t", "service": "s", "severity": "SEV-1",
               "transcript": "[ev_001] a\n[ev_002] b\n[ev_003] checkout is already at its scaling limit",
               "allowedRootCauses": ["capacity", "bad_deploy"]},
  "toolCatalog": [{"name": n, "description": "", "inputSchema": {"type": "object"}} for n in ("query_metrics", "scale_service", "page_owner")],
  "policy": {"maximumDiagnostics": 3, "effectTools": ["scale_service", "page_owner"], "approvalRequiredFor": [], "doNotExport": []},
}

def run(script):
    it = iter(script); calls.clear()
    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json); return next(it)
    planner.httpx.post = fake_post
    return planner.plan_incident(req)

# 1) provider rejects temperature/response_format -> falls back; reply wrapped in a code fence
out = run([R(400, ""), R(200, "```json\n" + json.dumps(GOOD) + "\n```")])
assert out["effectTool"] == "page_owner" and len(out["diagnostics"]) == 2
assert "response_format" not in calls[1]; print("ok: 400 fallback + fenced JSON + same tool twice")

# 2) model scales at the limit -> corrective retry -> pages the owner
bad = dict(GOOD, effectTool="scale_service")
out = run([R(200, json.dumps(bad)), R(200, json.dumps(GOOD))])
assert out["effectTool"] == "page_owner" and len(calls) == 2
assert "scaling limit" in calls[1]["messages"][-1]["content"]; print("ok: corrected scale->page after feedback")

# 3) two bad answers -> clean PlanningError, no crash
try: run([R(200, json.dumps(bad)), R(200, json.dumps(bad))]); raise SystemExit("should fail")
except planner.PlanningError: print("ok: gives up cleanly after 2 bad answers")
