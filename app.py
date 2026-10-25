from copy import deepcopy


import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("incident_agent")


from pydantic import ValidationError

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from incident.planner import PlanningError, plan_incident
from incident.schemas import IncidentRequest, ReceiptRequest
from incident.state_machine import (
    create_initial_state,
    process_receipt,
)
from incident.storage import (
    create_run,
    fingerprint,
    get_run,
    replace_state,
    update_run,
)
from incident.telemetry import (
    finish_model_span,
    start_trace,
)

app = FastAPI(
    title="Observable Incident Triage",
    version="2.0.0",
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    # Never return submitted input or sensitive values: report field paths only.
    fields = []
    for err in exc.errors()[:10]:
        fields.append(".".join(str(part) for part in err.get("loc", ())))
    logger.warning("Request validation failed on: %s", fields)
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid request", "fields": fields},
    )


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/v2/incidents")
async def create_incident(body: IncidentRequest, request: Request):
    data = body.model_dump(mode="json")
    run_id = data["runId"]

    if data["profile"] != "ga5-incident-agent/v2":
        return JSONResponse(
            status_code=400,
            content={"error": "Unsupported profile"},
        )

    request_hash = fingerprint(data)

    # Idempotent replay: do not invoke the model again.
    existing = get_run(run_id)
    if existing is not None:
        if existing["request_hash"] != request_hash:
            return JSONResponse(
                status_code=409,
                content={"error": "Run ID content conflict"},
            )

        saved = existing["state"].get("createdResponse")
        if saved is None:
            return JSONResponse(
                status_code=409,
                content={"error": "Run initialization in progress"},
            )
        return JSONResponse(content=saved)

    placeholder = {
        "runId": run_id,
        "status": "planning",
        "createdResponse": None,
        "lastResponse": None,
        "receiptResponses": {},
    }

    if not create_run(run_id, request_hash, placeholder):
        # A concurrent request may have inserted the same run.
        existing = get_run(run_id)
        if existing is None or existing["request_hash"] != request_hash:
            return JSONResponse(
                status_code=409,
                content={"error": "Run ID content conflict"},
            )

        saved = existing["state"].get("createdResponse")
        if saved is None:
            return JSONResponse(
                status_code=409,
                content={"error": "Run initialization in progress"},
            )
        return JSONResponse(content=saved)

    trace = start_trace(
        run_id=run_id,
        agent_name=data["agentName"],
        public_marker=data["publicMarker"],
        traceparent=request.headers.get("traceparent"),
        tracestate=request.headers.get("tracestate"),
    )

    try:
        # The planner only uses incident, catalog and policy.
        # The sensitive object is never passed to it.
        plan_input = {
            "runId": data["runId"],
            "agentName": data["agentName"],
            "publicMarker": data["publicMarker"],
            "incident": data["incident"],
            "toolCatalog": data["toolCatalog"],
            "policy": data["policy"],
        }

        plan = plan_incident(plan_input)
        finish_model_span(trace, plan["modelName"])

        state = create_initial_state(data, plan, trace)

        # Store the complete initial state before responding.
        replace_state(run_id, state)
        return JSONResponse(content=state["createdResponse"])

    # except PlanningError:
    #     failed = {
    #         "runId": run_id,
    #         "status": "failed",
    #         "diagnosis": None,
    #         "chosenEffect": None,
    #         "suppressed": [],
    #         "actionLog": [],
    #         "receiptLog": [],
    #         "otlp": {
    #             "resourceSpans": [{
    #                 "scopeSpans": [{
    #                     "spans": trace["spans"],
    #                 }],
    #             }],
    #         },
    #     }
    #     replace_state(run_id, {
    #         **placeholder,
    #         "status": "failed",
    #         "lastResponse": failed,
    #         "createdResponse": failed,
    #     })
    #     return JSONResponse(status_code=422, content=failed)

    # Inside create_incident(), replace the existing PlanningError handler:
    except PlanningError as exc:
        logger.warning(
            "Incident planning rejected for run %s: %s",
            run_id, str(exc),
        )
        failed = {
            "runId": run_id,
            "status": "failed",
            "error": "planning_failed: " + str(exc)[:200],
            "diagnosis": None,
            "chosenEffect": None,
            "suppressed": [],
            "actionLog": [],
            "receiptLog": [],
            "otlp": {
                "resourceSpans": [{
                    "scopeSpans": [{
                        "spans": trace["spans"],
                    }],
                }],
            },
        }
        replace_state(run_id, {
            **placeholder,
            "status": "failed",
            "lastResponse": failed,
            "createdResponse": failed,
        })
        return JSONResponse(status_code=422, content=failed)

    except Exception:
        # Do not expose exception text, model responses or credentials.
        return JSONResponse(
            status_code=500,
            content={"error": "Incident initialization failed"},
        )


@app.post("/v2/incidents/{runId}/receipts")
async def submit_receipt(runId: str, request: Request):
    # Hash the RAW body, so a change to any field (even one the schema ignores)
    # counts as changed content and yields 409 on the same receiptId.
    try:
        raw = await request.json()
        body = ReceiptRequest.model_validate(raw)
    except (ValueError, ValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": "Invalid request"},
        )

    current = get_run(runId)

    if current is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Run not found"},
        )

    receipt_hash = fingerprint(raw)
    receipt_id = body.receiptId

    def transition(state):
        if state.get("status") in ("planning",):
            raise ValueError("Run is not ready")

        saved = state.setdefault("receiptResponses", {})
        previous = saved.get(receipt_id)

        if previous is not None:
            if previous["hash"] != receipt_hash:
                raise ReceiptConflict()
            return deepcopy(previous["response"])

        # process_receipt is deterministic and performs no model call.
        response = process_receipt(state, body)
        saved[receipt_id] = {
            "hash": receipt_hash,
            "response": deepcopy(response),
        }
        state["lastResponse"] = deepcopy(response)
        return response

    try:
        result = update_run(runId, transition)
        if result is None:
            return JSONResponse(
                status_code=404,
                content={"error": "Run not found"},
            )
        return JSONResponse(content=result)

    except ReceiptConflict:
        return JSONResponse(
            status_code=409,
            content={"error": "Receipt ID content conflict"},
        )

    except ValueError:
        return JSONResponse(
            status_code=422,
            content={"error": "Invalid state transition"},
        )

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Receipt processing failed"},
        )


class ReceiptConflict(Exception):
    pass


@app.get("/v2/incidents/{runId}")
def get_incident(runId: str):
    existing = get_run(runId)

    if existing is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Run not found"},
        )

    state = existing["state"]
    response = state.get("lastResponse")

    if response is None:
        return JSONResponse(
            status_code=409,
            content={"error": "Run initialization in progress"},
        )

    return JSONResponse(content=response)
