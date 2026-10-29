from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    Boolean,
    DateTime,
    ForeignKey
)

from backend.database import Base


class Analysis(Base):

    __tablename__ = "analyses"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    report = Column(
        Text,
        nullable=False
    )

    mitre_version = Column(
        String(50),
        default="19.2"
    )

    model_version = Column(
        String(50),
        default="1.0.0"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class TechniqueResult(Base):

    __tablename__ = "technique_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    analysis_id = Column(
        Integer,
        ForeignKey(
            "analyses.id"
        ),
        nullable=False
    )

    technique_id = Column(
        String(50),
        nullable=False
    )

    technique_name = Column(
        String(255),
        nullable=False
    )

    tactic = Column(
        String(255)
    )

    ml_score = Column(
        Float
    )

    semantic_score = Column(
        Float
    )

    evidence_score = Column(
        Float
    )

    final_score = Column(
        Float
    )

    evidence = Column(
        Text
    )

    context = Column(
        String(100)
    )

    status = Column(
        String(50)
    )

    explanation = Column(
        Text
    )


class AnalystFeedback(Base):

    __tablename__ = "analyst_feedback"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    analysis_id = Column(
        Integer,
        ForeignKey(
            "analyses.id"
        ),
        nullable=False
    )

    technique_id = Column(
        String(50),
        nullable=False
    )

    correct = Column(
        Boolean,
        nullable=False
    )

    corrected_technique_id = Column(
        String(50),
        nullable=True
    )

    comment = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )