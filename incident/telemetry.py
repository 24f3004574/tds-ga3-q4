
import re
import secrets
import time


def new_id(length: int) -> str:
    return secrets.token_hex(length // 2)


def now_ns() -> str:
    return str(time.time_ns())


def attr(key, value):
    if isinstance(value, bool):
        typed = {"boolValue": value}
    elif isinstance(value, int):
        typed = {"intValue": str(value)}
    elif isinstance(value, float):
        typed = {"doubleValue": value}
    else:
        typed = {"stringValue": str(value)}
    return {"key": key, "value": typed}


def attributes(**values):
    return [attr(k, v) for k, v in values.items() if v is not None]


def parse_trace_context(traceparent, tracestate):
    """Validate W3C traceparent; reject zero IDs and unsupported versions."""
    pattern = (
        r"^([0-9a-f]{2})-([0-9a-f]{32})-"
        r"([0-9a-f]{16})-([0-9a-f]{2})$"
    )

    if traceparent:
        match = re.fullmatch(pattern, traceparent)
        if match:
            version, trace_id, parent_id, flags = match.groups()
            if (
                version != "ff"
                and trace_id != "0" * 32
                and parent_id != "0" * 16
                and (version == "00" or version != "00")
            ):
                return {
                    "traceId": trace_id,
                    "parentSpanId": parent_id,
                    "flags": flags,
                    "tracestate": tracestate or "",
                }

    return {
        "traceId": new_id(32),
        "parentSpanId": None,
        "flags": "01",
        "tracestate": "",
    }


def make_span(
    trace_id,
    span_id,
    parent_span_id,
    name,
    kind,
    run_id,
    public_marker,
    trace_state="",
    start=None,
    end=None,
    extra=None,
    status_code=0,
):
    stamp = now_ns()
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": start or stamp,
        "endTimeUnixNano": end or stamp,
        "attributes": attributes(
            **{
                "ga5.run.id": run_id,
                "ga5.public.marker": public_marker,
            }
        ),
        "status": {"code": status_code},
    }

    if parent_span_id:
        span["parentSpanId"] = parent_span_id

    if trace_state:
        span["traceState"] = trace_state

    if extra:
        span["attributes"].extend(
            attr(k, v) for k, v in extra.items() if v is not None
        )

    return span


def add_attribute(span, key, value):
    """Replace an attribute instead of creating duplicate keys."""
    span["attributes"] = [
        a for a in span.get("attributes", [])
        if a["key"] != key
    ]
    if value is not None:
        span["attributes"].append(attr(key, value))


def get_attribute(span, key):
    for item in span.get("attributes", []):
        if item["key"] == key:
            value = item["value"]
            for kind in ("stringValue", "intValue", "boolValue"):
                if kind in value:
                    return value[kind]
    return None


def start_trace(run_id, agent_name, public_marker, traceparent, tracestate):
    context = parse_trace_context(traceparent, tracestate)
    trace_id = context["traceId"]
    state = context["tracestate"]

    server_id = new_id(16)
    agent_id = new_id(16)
    model_id = new_id(16)

    server = make_span(
        trace_id, server_id, context["parentSpanId"],
        "POST /v2/incidents", 2, run_id, public_marker, state,
    )
    agent = make_span(
        trace_id, agent_id, server_id,
        f"invoke_agent {agent_name}", 1, run_id, public_marker, state,
    )
    model = make_span(
        trace_id, model_id, agent_id,
        "chat incident-plan", 3, run_id, public_marker, state,
        extra={
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "pending",
        },
    )

    return {
        "traceId": trace_id,
        "flags": context["flags"],
        "tracestate": state,
        "serverSpanId": server_id,
        "agentSpanId": agent_id,
        "modelSpanId": model_id,
        "spans": [server, agent, model],
        "toolSpanByAction": {},
        "clientSpanByAttempt": {},
        "joinSpanId": None,
        "approvalSpanId": None,
    }


def finish_model_span(trace, model_name):
    span_id = trace["modelSpanId"]
    for span in trace["spans"]:
        if span["spanId"] == span_id:
            add_attribute(span, "gen_ai.request.model", model_name)
            span["endTimeUnixNano"] = now_ns()
            return


def add_tool_dispatch(
    trace,
    run_id,
    public_marker,
    action_id,
    call_id,
    tool_name,
    attempt,
):
    """Create one logical execute_tool span and one physical CLIENT span."""
    trace_id = trace["traceId"]
    agent_id = trace["agentSpanId"]
    state = trace["tracestate"]

    logical_id = trace["toolSpanByAction"].get(action_id)

    if logical_id is None:
        logical_id = new_id(16)
        logical = make_span(
            trace_id,
            logical_id,
            agent_id,
            f"execute_tool {tool_name}",
            1,
            run_id,
            public_marker,
            state,
            extra={
                "ga5.action.id": action_id,
                "gen_ai.tool.name": tool_name,
                "gen_ai.tool.call.id": call_id,
                "gen_ai.operation.name": "execute_tool",
            },
        )
        trace["spans"].append(logical)
        trace["toolSpanByAction"][action_id] = logical_id

    client_id = new_id(16)
    client = make_span(
        trace_id,
        client_id,
        logical_id,
        f"POST tool/{tool_name}",
        3,
        run_id,
        public_marker,
        state,
        extra={
            "ga5.action.id": action_id,
            "ga5.attempt": attempt,
            "http.request.method": "POST",
            "http.request.resend_count": attempt - 1,
        },
    )

    trace["spans"].append(client)
    trace["clientSpanByAttempt"][f"{action_id}:{attempt}"] = client_id

    return f"00-{trace_id}-{client_id}-{trace['flags']}"


def record_tool_outcome(
    trace, action_id, attempt, receipt_id, outcome
):
    client_id = trace["clientSpanByAttempt"].get(
        f"{action_id}:{attempt}"
    )
    if not client_id:
        raise ValueError("Missing CLIENT span for observed outcome")

    span = next(
        s for s in trace["spans"] if s["spanId"] == client_id
    )

    add_attribute(span, "ga5.receipt.id", receipt_id)
    add_attribute(span, "ga5.receipt.nonce", outcome.get("nonce"))

    status = outcome["status"]

    if status == 0:
        add_attribute(span, "error.type", "timeout")
        span["status"] = {"code": 2, "message": "timeout"}
    elif status == 503:
        add_attribute(span, "http.response.status_code", 503)
        add_attribute(span, "error.type", "503")
        span["status"] = {"code": 2, "message": "503"}
    elif status == 200:
        add_attribute(span, "http.response.status_code", 200)
        span["status"] = {"code": 1}
    else:
        add_attribute(span, "http.response.status_code", status)
        add_attribute(span, "error.type", str(status))
        span["status"] = {"code": 2, "message": str(status)}

    span["endTimeUnixNano"] = now_ns()


def add_join(trace, run_id, public_marker, action_ids):
    if len(action_ids) < 2:
        return

    join_id = new_id(16)
    links = []

    for action_id in action_ids:
        logical_id = trace["toolSpanByAction"].get(action_id)
        if logical_id:
            links.append({
                "traceId": trace["traceId"],
                "spanId": logical_id,
                "attributes": [],
            })

    span = make_span(
        trace["traceId"],
        join_id,
        trace["agentSpanId"],
        "incident.join",
        1,
        run_id,
        public_marker,
        trace["tracestate"],
    )
    span["links"] = links
    trace["spans"].append(span)
    trace["joinSpanId"] = join_id


def add_approval_gate(
    trace, run_id, public_marker, approval_id, nonce=None
):
    if trace.get("approvalSpanId") is None:
        span_id = new_id(16)
        span = make_span(
            trace["traceId"],
            span_id,
            trace["agentSpanId"],
            "approval_gate",
            1,
            run_id,
            public_marker,
            trace["tracestate"],
            extra={"ga5.approval.id": approval_id},
        )
        trace["spans"].append(span)
        trace["approvalSpanId"] = span_id

    span = next(
        s for s in trace["spans"]
        if s["spanId"] == trace["approvalSpanId"]
    )
    add_attribute(span, "ga5.approval.id", approval_id)

    if nonce:
        add_attribute(span, "ga5.approval.receipt.nonce", nonce)
        add_attribute(span, "ga5.approval.nonce", nonce)
        add_attribute(span, "ga5.receipt.nonce", nonce)
        span["endTimeUnixNano"] = now_ns()


def finalize_trace(trace):
    """Make parent spans enclose their children (SERVER/agent/logical tool/join)."""
    spans = trace["spans"]
    by_id = {s["spanId"]: s for s in spans}
    children = {}
    for s in spans:
        children.setdefault(s.get("parentSpanId"), []).append(s)

    def visit(span):
        end = int(span["endTimeUnixNano"])
        for child in children.get(span["spanId"], []):
            end = max(end, visit(child))
        span["endTimeUnixNano"] = str(end)
        return end

    for s in spans:
        if s.get("parentSpanId") not in by_id:  # roots (SERVER span)
            visit(s)


def export_otlp(trace, agent_name):
    """Build an OTLP JSON export without prompts, bodies, or tool arguments."""
    return {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    attr("service.name", agent_name),
                ],
            },
            "scopeSpans": [{
                "scope": {"name": "incident-agent"},
                "spans": trace["spans"],
            }],
        }],
    }
