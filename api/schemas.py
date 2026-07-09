from typing import Annotated, Literal, Optional

from pydantic import BaseModel, Field

# Score convention (group decision, Jul 2026): every score in the system is a
# SAFETY score on a 0-10 scale — 10 = clearly safe, 0 = clearly a scam.
# Thresholds match the extension's toVerdict(): >=7 safe, 4-6 uncertain, <=3 scam.
# There is no risk scale anywhere; nothing is ever inverted on the wire.


class AnalyzeRequest(BaseModel):
    url: str = Field(max_length=2048)
    text: str = Field(max_length=1500)
    heuristic_score: int = Field(ge=0, le=10)  # safety scale, 10 = safe — same as HeuristicResult.score
    context: Literal["page_body", "email_body", "sms", "form"]
    title: Optional[str] = Field(default=None, max_length=300)
    meta_description: Optional[str] = Field(default=None, max_length=500)
    heuristic_verdict: Optional[Literal["safe", "uncertain", "scam"]] = None
    heuristic_findings: Optional[list[Annotated[str, Field(max_length=300)]]] = Field(
        default=None, max_length=20
    )


class AnalyzeResponse(BaseModel):
    safety_score: int = Field(ge=0, le=10)  # safety scale, 10 = safe — same as HeuristicResult.score
    label: Literal["safe", "uncertain", "scam"]
    action: Literal["allow", "warn", "block"]
    reason: str