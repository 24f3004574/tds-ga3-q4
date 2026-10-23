
import hashlib
import json
import uuid
from copy import deepcopy

from .telemetry import (
    add_approval_gate,
    add_join,
    add_tool_dispatch,
    record_tool_outcome,
)


def opaque(prefix):
    return f"{prefix}_{uuid.uuid4().hex}"


def arguments_digest(arguments):
    encoded = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def base_response(state):
    return {
        "runId": state["runId"],
        "status": state["status"],
        "diagnosis": deepcopy(state["diagnosis"]),
        "dispatches": [],
        "approvals": [],
    }


def make_dispatch(
    state,
    phase,
    tool_name,
    arguments,
    evidence,
    action_id=None,
    call_id=None,
    attempt=1,
    approval_id=None,
    approval_nonce=None,
):
    action_id = action_id or opaque("action")
    call_id = call_id or opaque("call")

    traceparent = add_tool_dispatch(
        state["trace"],
        state["runId"],
        state["publicMarker"],
        action_id,
        call_id,
        tool_name,
        attempt,
    )

    dispatch = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "arguments": deepcopy(arguments),
        "evidence": list(evidence),
        "attempt": attempt,
        "traceparent": traceparent,
    }

    if approval_id:
        dispatch["approvalId"] = approval_id
        dispatch["approvalNonce"] = approval_nonce

    state["actionLog"].append(deepcopy(dispatch))

    state["pending"][action_id] = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "arguments": deepcopy(arguments),
        "evidence": list(evidence),
        "attempt": attempt,
        "approvalId": approval_id,
    }

    return dispatch


def terminal_response(state, status):
    state["status"] = status
    state["pending"] = {}
    state["pendingApproval"] = None

    result = {
        "runId": state["runId"],
        "status": status,
        "diagnosis": deepcopy(state["diagnosis"]),
        "chosenEffect": state.get("chosenEffect"),
        "suppressed": deepcopy(state["suppressed"]),
        "actionLog": deepcopy(state["actionLog"]),
        "receiptLog": deepcopy(state["receiptLog"]),
        "otlp": {
            "resourceSpans": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": {
                            "stringValue": state["agentName"]
                        },
                    }],
                },
                "scopeSpans": [{
                    "scope": {"name": "incident-agent"},
                    "spans": state["trace"]["spans"],
                }],
            }],
        },
    }

    state["lastResponse"] = deepcopy(result)
    return result


def waiting_response(state, dispatches=None, approvals=None):
    result = base_response(state)
    result["dispatches"] = deepcopy(dispatches or [])
    result["approvals"] = deepcopy(approvals or [])
    state["lastResponse"] = deepcopy(result)
    return result


def create_initial_state(request_data, plan, trace):
    run_id = request_data["runId"]
    incident = request_data["incident"]
    policy = request_data["policy"]

    state = {
        "runId": run_id,
        "agentName": request_data["agentName"],
        "publicMarker": request_data["publicMarker"],
        "status": "waiting",
        "diagnosis": deepcopy(plan["diagnosis"]),
        "trace": trace,
        "actionLog": [],
        "receiptLog": [],
        "pending": {},
        "pendingApproval": None,
        "receiptResponses": {},
        "diagnosticActionIds": [],
        "diagnosticResults": {},
        "effectTool": plan["effectTool"],
        "effectArguments": deepcopy(plan["effectArguments"]),
        "effectActionId": opaque("action"),
        "effectCallId": opaque("call"),
        "chosenEffect": None,
        "suppressed": [],
        "approvalRequiredFor": list(
            policy.get("approvalRequiredFor", [])
        ),
        "createdResponse": None,
        "lastResponse": None,
    }

    dispatches = []

    for diagnostic in plan["diagnostics"]:
        dispatch = make_dispatch(
            state,
            phase="diagnostic",
            tool_name=diagnostic["toolName"],
            arguments=diagnostic["arguments"],
            evidence=diagnostic["evidence"],
        )
        dispatches.append(dispatch)
        state["diagnosticActionIds"].append(dispatch["actionId"])
        state["diagnosticResults"][dispatch["actionId"]] = "pending"

    if len(dispatches) > 1:
        add_join(
            trace,
            run_id,
            request_data["publicMarker"],
            state["diagnosticActionIds"],
        )

    response = waiting_response(state, dispatches=dispatches)
    state["createdResponse"] = deepcopy(response)
    return state


def fail_for_diagnostic(state, action, reason):
    state["suppressed"].append({
        "toolName": state["effectTool"],
        "reason": reason,
    })
    state["diagnosticResults"][action["actionId"]] = "failed"
    return terminal_response(state, "failed")


def begin_effect(state):
    effect_name = state["effectTool"]
    arguments = state["effectArguments"]
    evidence = state["diagnosis"]["evidence"]
    action_id = state["effectActionId"]
    call_id = state["effectCallId"]

    state["chosenEffect"] = effect_name

    if effect_name in state["approvalRequiredFor"]:
        approval_id = opaque("approval")
        digest = arguments_digest(arguments)

        state["pendingApproval"] = {
            "approvalId": approval_id,
            "actionId": action_id,
            "callId": call_id,
            "toolName": effect_name,
            "arguments": deepcopy(arguments),
            "argumentsDigest": digest,
            "evidence": evidence,
        }

        add_approval_gate(
            state["trace"],
            state["runId"],
            state["publicMarker"],
            approval_id,
        )

        return waiting_response(
            state,
            dispatches=[],
            approvals=[{
                "approvalId": approval_id,
                "actionId": action_id,
                "toolName": effect_name,
                "argumentsDigest": digest,
            }],
        )

    dispatch = make_dispatch(
        state,
        phase="effect",
        tool_name=effect_name,
        arguments=arguments,
        evidence=evidence,
        action_id=action_id,
        call_id=call_id,
    )

    return waiting_response(state, dispatches=[dispatch])


def process_receipt(state, receipt):
    if state["status"] in ("completed", "failed"):
        raise ValueError("Run is already terminal")

    emitted_dispatches = []

    # Validate every outcome against the currently pending attempt.
    for outcome_model in receipt.outcomes:
        outcome = outcome_model.model_dump(exclude_none=True)
        action_id = outcome["actionId"]
        action = state["pending"].get(action_id)

        if action is None:
            raise ValueError("Outcome does not match a pending action")

        if (
            outcome["callId"] != action["callId"]
            or outcome["attempt"] != action["attempt"]
        ):
            raise ValueError("Outcome call or attempt mismatch")

    # Validate every approval before making any state transition.
    for approval_model in receipt.approvals:
        approval = approval_model.model_dump()
        pending = state.get("pendingApproval")

        if not pending or approval["approvalId"] != pending["approvalId"]:
            raise ValueError("Approval does not match pending request")

    receipt_id = receipt.receiptId

    # Record and process tool outcomes.
    for outcome_model in receipt.outcomes:
        outcome = outcome_model.model_dump(exclude_none=True)
        action_id = outcome["actionId"]
        action = deepcopy(state["pending"][action_id])

        record_tool_outcome(
            state["trace"],
            action_id,
            outcome["attempt"],
            receipt_id,
            outcome,
        )

        record = {
            "receiptId": receipt_id,
            "actionId": action_id,
            "callId": action["callId"],
            "attempt": action["attempt"],
            "status": outcome["status"],
            "resultClass": outcome.get("resultClass"),
            "nonce": outcome.get("nonce"),
        }
        if outcome.get("errorType"):
            record["errorType"] = outcome["errorType"]

        state["receiptLog"].append(record)
        del state["pending"][action_id]

        status = outcome["status"]

        if action["phase"] == "diagnostic":
            if status == 503 and action["attempt"] == 1:
                # One retry only: preserve logical IDs.
                retry = make_dispatch(
                    state,
                    phase="diagnostic",
                    tool_name=action["toolName"],
                    arguments=action["arguments"],
                    evidence=action["evidence"],
                    action_id=action_id,
                    call_id=action["callId"],
                    attempt=2,
                )
                emitted_dispatches.append(retry)
                state["diagnosticResults"][action_id] = "pending"

            elif status == 200:
                state["diagnosticResults"][action_id] = "success"

            elif status == 0:
                state["diagnosticResults"][action_id] = "failed"
                state["suppressed"].append({
                    "toolName": state["effectTool"],
                    "reason": "diagnostic_timeout",
                })

            else:
                state["diagnosticResults"][action_id] = "failed"

        else:
            # The effect is terminal after its one observed result.
            if status == 200:
                return terminal_response(state, "completed")
            return terminal_response(state, "failed")

    # A diagnostic failure suppresses the dependent effect.
    if any(
        result == "failed"
        for result in state["diagnosticResults"].values()
    ):
        return terminal_response(state, "failed")

    
    # Wait for outstanding calls before advancing the state machine.
    if state["pending"]:
        return waiting_response(state, dispatches=emitted_dispatches)

    # Process an approval before considering starting another effect.
    for approval_model in receipt.approvals:
        approval = approval_model.model_dump()
        pending = state.get("pendingApproval")

        if not pending:
            raise ValueError("No pending approval")

        state["receiptLog"].append({
            "receiptId": receipt.receiptId,
            "approvalId": approval["approvalId"],
            "decision": approval["decision"],
            "nonce": approval["nonce"],
        })

        add_approval_gate(
            state["trace"],
            state["runId"],
            state["publicMarker"],
            approval["approvalId"],
            approval["nonce"],
        )

        if approval["decision"] != "approved":
            state["suppressed"].append({
                "toolName": pending["toolName"],
                "reason": "approval_rejected",
            })
            return terminal_response(state, "failed")

        if (
            arguments_digest(pending["arguments"])
            != pending["argumentsDigest"]
        ):
            raise ValueError("Approval digest mismatch")

        state["pendingApproval"] = None

        dispatch = make_dispatch(
            state,
            phase="effect",
            tool_name=pending["toolName"],
            arguments=pending["arguments"],
            evidence=pending["evidence"],
            action_id=pending["actionId"],
            call_id=pending["callId"],
            approval_id=pending["approvalId"],
            approval_nonce=approval["nonce"],
        )

        return waiting_response(state, dispatches=[dispatch])

    # Start an effect only after every diagnostic succeeds.
    if state["diagnosticResults"] and all(
        result == "success"
        for result in state["diagnosticResults"].values()
    ):
        if state.get("pendingApproval"):
            return waiting_response(state)

        if not state.get("chosenEffect"):
            return begin_effect(state)

    return waiting_response(state, dispatches=emitted_dispatches)

    # Do not issue an effect until every diagnostic succeeded.
    if state["diagnosticResults"] and all(
        result == "success"
        for result in state["diagnosticResults"].values()
    ):
        if state.get("pendingApproval"):
            return waiting_response(state)

        # An effect must be issued only once.
        if not state.get("chosenEffect"):
            return begin_effect(state)

    # Process an approval only after all diagnostics have succeeded.
    for approval_model in receipt.approvals:
        approval = approval_model.model_dump()
        pending = state.get("pendingApproval")

        if not pending:
            raise ValueError("No pending approval")

        state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": approval["approvalId"],
            "decision": approval["decision"],
            "nonce": approval["nonce"],
        })

        add_approval_gate(
            state["trace"],
            state["runId"],
            state["publicMarker"],
            approval["approvalId"],
            approval["nonce"],
        )

        if approval["decision"] != "approved":
            state["suppressed"].append({
                "toolName": pending["toolName"],
                "reason": "approval_rejected",
            })
            return terminal_response(state, "failed")

        # Recompute the digest to protect the approval boundary.
        if (
            arguments_digest(pending["arguments"])
            != pending["argumentsDigest"]
        ):
            raise ValueError("Approval digest mismatch")

        state["pendingApproval"] = None

        dispatch = make_dispatch(
            state,
            phase="effect",
            tool_name=pending["toolName"],
            arguments=pending["arguments"],
            evidence=pending["evidence"],
            action_id=pending["actionId"],
            call_id=pending["callId"],
            approval_id=pending["approvalId"],
            approval_nonce=approval["nonce"],
        )

        return waiting_response(state, dispatches=[dispatch])

    return waiting_response(state, dispatches=emitted_dispatches)
