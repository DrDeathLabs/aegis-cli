from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceObservation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    role: str
    conclusion: str
    confidence: float = 0.5
    evidence_refs: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, value):
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.5


class ChallengeResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    disposition: Literal["confirmed", "unconfirmed", "false_positive", "mitigated", "accepted_risk", "remediated"] = "confirmed"
    rationale: str = ""
    conflicts: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class MockModelResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    conclusion: str = "evidence insufficient"
    confidence: float = 0.5
    rationale: str = ""
