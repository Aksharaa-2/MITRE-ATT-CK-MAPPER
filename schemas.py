from typing import Optional, List

from pydantic import (
    BaseModel,
    Field
)


class AnalyzeRequest(BaseModel):

    report: str = Field(
        ...,
        min_length=10,
        max_length=100000
    )


class FeedbackRequest(BaseModel):

    analysis_id: int

    technique_id: str

    correct: bool

    corrected_technique_id: Optional[
        str
    ] = None

    comment: Optional[
        str
    ] = Field(
        default=None,
        max_length=5000
    )


class TechniqueResponse(BaseModel):

    technique_id: str

    technique_name: str

    tactics: str

    platforms: str

    ml_score: float

    semantic_score: float

    evidence_score: float

    final_score: float

    evidence: str

    context: str

    status: str

    uncertain: bool

    negated: bool

    explanation: str


class AnalyzeResponse(BaseModel):

    analysis_id: int

    mitre_version: str

    model_version: str

    results: List[
        TechniqueResponse
    ]

    attack_sequence: list