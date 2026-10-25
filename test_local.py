"""Local fake grader. Run:  python test_local.py
Mocks the model call, then drives the API like the grader does and checks
the rules from the assignment text (best effort, the real grader has more)."""
import copy, hashlib, json, os, uuid, tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"

from fastapi.testclient import TestClient
import app as appmod

client = TestClient(appmod.app)
FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("  FAIL:", msg)


def make_request(run_id, effect="scale_service"):
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "marker-" + run_id[-6:],
        "sensitive": {"accessToken": "TOKEN-CANARY-123", "privateNote": "NOTE-CANARY-456"},
        "incident": {
            "incidentId": "inc-1", "title": "t", "service": "checkout", "severity": "SEV-1",
            "transcript": "[ev_001] one\n[ev_002] two\n[ev_003] three\n[ev_004] four",
            "allowedRootCauses": ["bad_deploy", "capacity"],
        },
        "toolCatalog": [
            {"name": "query_metrics", "description": "", "inputSchema": {"type": "object"}},
            {"name": "query_logs", "description": "", "inputSchema": {"type": "object"}},
            {"name": "scale_service", "description": "", "inputSchema": {"type": "object"}},
            {"name": "page_owner", "description": "", "inputSchema": {"type": "object"}},
            {"name": "rollback_deployment", "description": "", "inputSchema": {"type": "object"}},
        ],
        "policy": {
            "maximumDiagnostics": 3, "effectTools": [effect],
            "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
            "doNotExport": ["accessToken"],
        },
    }


def fake_plan(n_diag, effect):
    def _plan(_input):
        diags = [
            {"toolName": ["query_metrics", "query_logs"][i], "arguments": {"service": "checkout"},
             "evidence": ["ev_001"]}
            for i in range(n_diag)
        ]
        return {
            "diagnosis": {"rootCause": "capacity", "evidence": ["ev_001", "ev_002"]},
            "diagnostics": diags, "effectTool": effect,
            "effectArguments": {"service": "checkout"}, "modelName": "fake-model",
        }
    return _plan


def outcome(d, status=200, **kw):
    o = {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"],
         "status": status, "resultClass": "diagnosis_confirmed", "nonce": str(uuid.uuid4())}
    if status == 0:
        o["errorType"] = "timeout"
    o.update(kw)
    return o


def receipt(outcomes=None, approvals=None):
    r = {"receiptId": "rcpt-" + uuid.uuid4().hex[:10]}
    if outcomes: r["outcomes"] = outcomes
    if approvals: r["approvals"] = approvals
    return r


SENT = {}


def post_rcpt(run_id, body):
    SENT.setdefault(run_id, []).append(copy.deepcopy(body))
    return client.post(f"/v2/incidents/{run_id}/receipts", json=body)


def attrs(span):
    out = {}
    for a in span["attributes"]:
        v = a["value"]
        out[a["key"]] = next(iter(v.values()))
    return out


def validate_trace(final, run_id, marker, tool_names_logical, expect_join, expect_approval):
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    ids = [s["spanId"] for s in spans]
    check(len(set(ids)) == len(ids), "span ids not unique")
    tids = {s["traceId"] for s in spans}
    check(len(tids) == 1, "more than one trace id")
    by_name = lambda p: [s for s in spans if s["name"].startswith(p)]
    check(len([s for s in spans if s["kind"] == 2]) == 1, "need exactly one SERVER span")
    check(len(by_name("chat incident-plan")) == 1, "need exactly one chat incident-plan")
    check(len(by_name("execute_tool")) == len(tool_names_logical),
          f"execute_tool count {len(by_name('execute_tool'))} != {len(tool_names_logical)}")
    for s in spans:
        a = attrs(s)
        check(a.get("ga5.run.id") == run_id, f"{s['name']} missing run id")
        check(a.get("ga5.public.marker") == marker, f"{s['name']} missing marker")
    # timing containment
    by_id = {s["spanId"]: s for s in spans}
    for s in spans:
        p = by_id.get(s.get("parentSpanId"))
        if p:
            if int(s["endTimeUnixNano"]) > int(p["endTimeUnixNano"]):
                check(False, f"child '{s['name']}' ends after parent '{p['name']}'")
                break
    # dispatch traceparent <-> client span
    for d in final["actionLog"]:
        sid = d["traceparent"].split("-")[2]
        check(sid in by_id and by_id[sid]["kind"] == 3, f"traceparent span {sid} is not a CLIENT span")
    # clients
    clients = [s for s in spans if s["name"].startswith("POST tool/")]
    check(len(clients) == len(final["actionLog"]), "CLIENT span count != dispatch count")
    for c in clients:
        a = attrs(c)
        for k in ("ga5.action.id", "ga5.attempt", "ga5.receipt.id", "ga5.receipt.nonce",
                  "http.request.method", "http.request.resend_count"):
            check(k in a, f"CLIENT span missing {k}")
    if expect_join:
        j = by_name("incident.join")
        check(len(j) == 1 and len(j[0].get("links", [])) >= 2, "join span/links wrong")
    if expect_approval:
        g = by_name("approval_gate")
        check(len(g) == 1, "approval_gate count")
    blob = json.dumps(final)
    check("TOKEN-CANARY-123" not in blob and "NOTE-CANARY-456" not in blob, "sensitive leaked")
    check("gen_ai.tool.call.arguments" not in blob, "tool arguments exported")


def scenario(name, n_diag, effect, steps):
    print(f"== {name}")
    run_id = "run-" + uuid.uuid4().hex[:12]
    appmod.plan_incident = fake_plan(n_diag, effect)
    req = make_request(run_id, effect)
    r = client.post("/v2/incidents", json=req,
                    headers={"traceparent": "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01",
                             "tracestate": "vendor=x"})
    check(r.status_code == 200, f"create status {r.status_code}")
    first = r.json()
    check(first["status"] == "waiting", "first status")
    check(1 <= len(first["dispatches"]) <= 3, "dispatch count")
    return run_id, req, first


# ---------- scenarios ----------
def run_parallel_success():
    run_id, req, first = scenario("parallel diagnostics + scale effect", 2, "scale_service", None)
    r = post_rcpt(run_id, receipt([outcome(d) for d in first["dispatches"]]))
    check(r.status_code == 200, f"receipt status {r.status_code}")
    eff = r.json()
    check(len(eff["dispatches"]) == 1 and eff["dispatches"][0]["phase"] == "effect", "effect not dispatched")
    r = post_rcpt(run_id, receipt([outcome(eff["dispatches"][0])]))
    final = r.json()
    check(final["status"] == "completed", f"final status {final.get('status')}")
    check(final.get("chosenEffect") == "scale_service", "chosenEffect")
    check(len(final["receiptLog"]) == 3, f"receiptLog len {len(final['receiptLog'])}")
    validate_trace(final, run_id, req["publicMarker"], ["a", "b", "c"], True, False)
    replay_checks(run_id, req, final)


def run_503_retry():
    run_id, req, first = scenario("503 then retry", 2, "scale_service", None)
    d0, d1 = first["dispatches"]
    r = post_rcpt(run_id, receipt([outcome(d0, 503), outcome(d1)]))
    j = r.json()
    check(len(j["dispatches"]) == 1 and j["dispatches"][0]["attempt"] == 2, "no attempt 2")
    check(j["dispatches"][0]["actionId"] == d0["actionId"], "retry changed actionId")
    check(j["dispatches"][0]["traceparent"] != d0["traceparent"], "retry reused span id")
    check(j["approvals"] == [], "retry has approvals")
    r = post_rcpt(run_id, receipt([outcome(j["dispatches"][0])]))
    eff = r.json()
    check(len(eff["dispatches"]) == 1 and eff["dispatches"][0]["phase"] == "effect", "effect after retry")
    r = post_rcpt(run_id, receipt([outcome(eff["dispatches"][0])]))
    final = r.json()
    check(final["status"] == "completed", "retry final status")
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    c503 = [s for s in spans if attrs(s).get("error.type") == "503"]
    check(len(c503) == 1 and c503[0]["status"]["code"] == 2, "503 span")
    check(attrs(c503[0]).get("http.request.resend_count") == "0", "503 resend count should be 0")
    retry = [s for s in spans if attrs(s).get("ga5.attempt") == "2"]
    check(len(retry) == 1 and attrs(retry[0]).get("http.request.resend_count") == "1", "retry resend count")
    validate_trace(final, run_id, req["publicMarker"], ["a", "b", "c"], True, False)


def run_timeout():
    run_id, req, first = scenario("timeout suppresses effect", 2, "scale_service", None)
    d0, d1 = first["dispatches"]
    r = post_rcpt(run_id, receipt([outcome(d0, 0), outcome(d1)]))
    final = r.json()
    check(final["status"] == "failed", "timeout should end failed")
    check(not any(d["phase"] == "effect" for d in final["actionLog"]), "effect sent after timeout")
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    t = [s for s in spans if attrs(s).get("error.type") == "timeout"]
    check(len(t) == 1 and t[0]["status"]["code"] == 2, "timeout span")
    validate_trace(final, run_id, req["publicMarker"], ["a", "b"], True, False)
    replay_checks(run_id, req, final)


def run_timeout_split():
    run_id, req, first = scenario("timeout arrives while sibling still pending", 2, "scale_service", None)
    d0, d1 = first["dispatches"]
    r = post_rcpt(run_id, receipt([outcome(d0, 0)]))
    j = r.json()
    r2 = post_rcpt(run_id, receipt([outcome(d1)]))
    print("   after timeout alone ->", j["status"], "| sibling receipt ->", r2.status_code)
    check(j["status"] != "failed" or r2.status_code == 200,
          "timeout alone ends the run and drops the sibling's receipt (sibling gets 4xx, action has no receipt)")


def run_approval():
    run_id, req, first = scenario("approval flow", 1, "rollback_deployment", None)
    r = post_rcpt(run_id, receipt([outcome(first["dispatches"][0])]))
    j = r.json()
    check(j["dispatches"] == [] and len(j["approvals"]) == 1, "should ask approval, zero dispatches")
    ap = j["approvals"][0]
    exp = hashlib.sha256(json.dumps({"service": "checkout"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    check(ap["argumentsDigest"] == exp, "digest mismatch")
    nonce = str(uuid.uuid4())
    r = post_rcpt(run_id, receipt(approvals=[{"approvalId": ap["approvalId"], "decision": "approved", "nonce": nonce}]))
    j = r.json()
    e = j["dispatches"][0]
    check(e["approvalId"] == ap["approvalId"] and e["approvalNonce"] == nonce, "approval fields on effect")
    check(e["actionId"] == ap["actionId"], "effect action id != approval action id")
    r = post_rcpt(run_id, receipt([outcome(e)]))
    final = r.json()
    check(final["status"] == "completed", "approval final")
    check(any("approvalId" in x for x in final["receiptLog"]), "approval receipt missing in receiptLog")
    validate_trace(final, run_id, req["publicMarker"], ["a", "b"], False, True)
    replay_checks(run_id, req, final)
    gate = [s for s in final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"] if s["name"] == "approval_gate"][0]
    check(nonce in json.dumps(gate), "approval nonce not on gate span")
    return run_id, req, final


def replay_checks(run_id, req, final):
    g = client.get(f"/v2/incidents/{run_id}")
    check(g.status_code == 200 and g.json() == final, "GET != final")
    r = client.post("/v2/incidents", json=req)
    check(r.status_code == 200, f"repeat create status {r.status_code}")
    changed = copy.deepcopy(req); changed["publicMarker"] = "other"
    r = client.post("/v2/incidents", json=changed)
    check(r.status_code == 409, f"changed run content should 409, got {r.status_code}")
    check("CANARY" not in r.text, "409 echoed sensitive")
    ident = copy.deepcopy(SENT[run_id][0])
    r = client.post(f"/v2/incidents/{run_id}/receipts", json=ident)
    check(r.status_code == 200, f"identical receipt replay got {r.status_code}")
    bad = copy.deepcopy(ident); bad["outcomes"][0]["nonce"] = "different-nonce"
    r = client.post(f"/v2/incidents/{run_id}/receipts", json=bad)
    check(r.status_code == 409, f"changed receipt should 409, got {r.status_code}")
    g2 = client.get(f"/v2/incidents/{run_id}")
    check(g2.json() == final, "state changed by replay/conflict probes")


def run_validation():
    print("== validation")
    r = client.post("/v2/incidents", json={**make_request("run-" + uuid.uuid4().hex[:12]), "profile": "nope"})
    check(r.status_code in (400, 422), f"bad profile {r.status_code}")
    r = client.post("/v2/incidents", json={"profile": "x"})
    check(r.status_code == 422, "bad body")
    r = post_rcpt("does-not-exist-xx", receipt([{"actionId": "a" * 8, "callId": "b" * 8, "attempt": 1, "status": 200, "nonce": "n"}]))
    check(r.status_code in (404, 400, 422), "unknown run")
    # extra field the grader might add
    run_id, req, first = scenario("receipt with an extra field", 1, "scale_service", None)
    o = outcome(first["dispatches"][0]); o["latencyMs"] = 12
    r = post_rcpt(run_id, receipt([o]))
    check(r.status_code == 200, f"extra field in outcome rejected with {r.status_code}")


for fn in (run_parallel_success, run_503_retry, run_timeout, run_timeout_split, run_approval, run_validation):
    try:
        fn()
    except Exception as e:  # noqa
        import traceback; traceback.print_exc()
        FAILS.append(f"{fn.__name__} crashed: {e!r}")

print("\n" + ("ALL GOOD" if not FAILS else f"{len(FAILS)} problem(s):"))
for f in FAILS:
    print(" -", f)
