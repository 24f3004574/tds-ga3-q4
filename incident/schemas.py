
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IncidentData(BaseModel):
    model_config = ConfigDict(extra="allow")

    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: list[str] = Field(min_length=1)


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    model_config = ConfigDict(extra="allow")

    maximumDiagnostics: int = Field(default=3, ge=1, le=3)
    effectTools: list[str] = Field(default_factory=list)
    approvalRequiredFor: list[str] = Field(default_factory=list)
    doNotExport: list[str] = Field(default_factory=list)


class IncidentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    profile: str
    runId: str = Field(min_length=8, max_length=200)
    agentName: str
    publicMarker: str
    sensitive: dict[str, Any] = Field(default_factory=dict)
    incident: IncidentData
    toolCatalog: list[ToolDefinition] = Field(min_length=1)
    policy: Policy


class ToolOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actionId: str = Field(min_length=8)
    callId: str = Field(min_length=8)
    attempt: int = Field(ge=1)
    status: int
    resultClass: str | None = None
    nonce: str | None = None
    errorType: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self):
        if self.status == 0:
            if self.errorType != "timeout":
                raise ValueError("Invalid transport failure")
        elif self.status < 100 or self.status > 599:
            raise ValueError("Invalid HTTP status")

        if self.status != 0 and not self.nonce:
            raise ValueError("Outcome nonce required")

        return self


class ApprovalOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approvalId: str = Field(min_length=8)
    decision: str
    nonce: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_decision(self):
        if self.decision not in ("approved", "rejected"):
            raise ValueError("Invalid approval decision")
        return self


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receiptId: str = Field(min_length=8)
    outcomes: list[ToolOutcome] = Field(default_factory=list)
    approvals: list[ApprovalOutcome] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_receipt(self):
        if not self.outcomes and not self.approvals:
            raise ValueError("Receipt must contain an outcome or approval")
        return self
