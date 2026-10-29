from fastapi import (
    FastAPI,
    HTTPException,
    Depends
)

from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from backend.database import (
    Base,
    engine,
    get_db
)

from backend.models import (
    Analysis,
    TechniqueResult,
    AnalystFeedback
)

from backend.schemas import (
    AnalyzeRequest,
    FeedbackRequest
)

from core.pipeline import (
    TechniqueMapper
)

from core.attack_sequence import (
    build_attack_sequence
)


MITRE_VERSION = "19.2"

MODEL_VERSION = "1.0.0"


# ------------------------------------------------------------
# Database
# ------------------------------------------------------------

Base.metadata.create_all(
    bind=engine
)


# ------------------------------------------------------------
# FastAPI
# ------------------------------------------------------------

app = FastAPI(
    title="MITRE ATT&CK Technique Mapper",
    description=(
        "Context-aware, evidence-based, "
        "hybrid ML MITRE ATT&CK technique "
        "mapping system."
    ),
    version=MODEL_VERSION
)


# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:8501"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)


# ------------------------------------------------------------
# Mapper
# ------------------------------------------------------------

try:

    mapper = TechniqueMapper()

    mapper_error = None

except Exception as e:

    mapper = None

    mapper_error = str(e)


# ------------------------------------------------------------
# Root
# ------------------------------------------------------------

@app.get("/")
def root():

    return {
        "service":
            "MITRE ATT&CK Technique Mapper",

        "status":
            "running",

        "mitre_version":
            MITRE_VERSION,

        "model_version":
            MODEL_VERSION
    }


# ------------------------------------------------------------
# Health
# ------------------------------------------------------------

@app.get("/health")
def health():

    if mapper is None:

        return {
            "status": "error",

            "mapper_loaded":
                False,

            "error":
                mapper_error
        }

    return {

        "status":
            "healthy",

        "mapper_loaded":
            True,

        "mitre_version":
            MITRE_VERSION,

        "model_version":
            MODEL_VERSION
    }


# ------------------------------------------------------------
# Analyze
# ------------------------------------------------------------

@app.post("/analyze")
def analyze(
    request: AnalyzeRequest,
    db: Session = Depends(get_db)
):

    if mapper is None:

        raise HTTPException(
            status_code=500,
            detail=(
                "Mapper failed to load: "
                + str(mapper_error)
            )
        )

    try:

        # ---------------------------------------------
        # Run intelligence pipeline
        # ---------------------------------------------

        results = mapper.analyze(
            request.report
        )

        # ---------------------------------------------
        # Build attack sequence
        # ---------------------------------------------

        sequence = build_attack_sequence(
            results
        )

        # ---------------------------------------------
        # Store analysis
        # ---------------------------------------------

        analysis = Analysis(

            report=request.report,

            mitre_version=
                MITRE_VERSION,

            model_version=
                MODEL_VERSION
        )

        db.add(
            analysis
        )

        db.commit()

        db.refresh(
            analysis
        )

        # ---------------------------------------------
        # Store technique results
        # ---------------------------------------------

        for result in results:

            tactics = result.get(
                "tactics",
                ""
            )

            if isinstance(
                tactics,
                list
            ):

                tactics = "|".join(
                    tactics
                )

            technique_result = (
                TechniqueResult(

                    analysis_id=
                        analysis.id,

                    technique_id=
                        result[
                            "technique_id"
                        ],

                    technique_name=
                        result[
                            "technique_name"
                        ],

                    tactic=
                        tactics,

                    ml_score=
                        result.get(
                            "ml_score",
                            0
                        ),

                    semantic_score=
                        result.get(
                            "semantic_score",
                            0
                        ),

                    evidence_score=
                        result.get(
                            "evidence_score",
                            0
                        ),

                    final_score=
                        result.get(
                            "final_score",
                            0
                        ),

                    evidence=
                        result.get(
                            "evidence",
                            ""
                        ),

                    context=
                        result.get(
                            "context",
                            ""
                        ),

                    status=
                        result.get(
                            "status",
                            ""
                        ),

                    explanation=
                        result.get(
                            "explanation",
                            ""
                        )
                )
            )

            db.add(
                technique_result
            )

        db.commit()

        # ---------------------------------------------
        # Response
        # ---------------------------------------------

        return {

            "analysis_id":
                analysis.id,

            "mitre_version":
                MITRE_VERSION,

            "model_version":
                MODEL_VERSION,

            "results":
                results,

            "attack_sequence":
                sequence
        }

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ------------------------------------------------------------
# Analyst feedback
# ------------------------------------------------------------

@app.post("/feedback")
def submit_feedback(
    request: FeedbackRequest,
    db: Session = Depends(get_db)
):

    analysis = db.query(
        Analysis
    ).filter(
        Analysis.id
        == request.analysis_id
    ).first()

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    feedback = AnalystFeedback(

        analysis_id=
            request.analysis_id,

        technique_id=
            request.technique_id,

        correct=
            request.correct,

        corrected_technique_id=
            request.corrected_technique_id,

        comment=
            request.comment
    )

    db.add(
        feedback
    )

    db.commit()

    db.refresh(
        feedback
    )

    return {

        "status":
            "feedback_recorded",

        "feedback_id":
            feedback.id,

        "message":
            (
                "Analyst feedback stored "
                "for future model evaluation "
                "and retraining."
            )
    }


# ------------------------------------------------------------
# Analysis history
# ------------------------------------------------------------

@app.get("/analyses")
def get_analyses(
    db: Session = Depends(get_db)
):

    analyses = (
        db.query(
            Analysis
        )
        .order_by(
            Analysis.created_at.desc()
        )
        .limit(50)
        .all()
    )

    return [

        {
            "id":
                analysis.id,

            "mitre_version":
                analysis.mitre_version,

            "model_version":
                analysis.model_version,

            "created_at":
                analysis.created_at
        }

        for analysis in analyses
    ]


# ------------------------------------------------------------
# Single analysis
# ------------------------------------------------------------

@app.get("/analyses/{analysis_id}")
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db)
):

    analysis = db.query(
        Analysis
    ).filter(
        Analysis.id
        == analysis_id
    ).first()

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    results = db.query(
        TechniqueResult
    ).filter(
        TechniqueResult.analysis_id
        == analysis_id
    ).all()

    return {

        "id":
            analysis.id,

        "report":
            analysis.report,

        "mitre_version":
            analysis.mitre_version,

        "model_version":
            analysis.model_version,

        "created_at":
            analysis.created_at,

        "results": [

            {

                "technique_id":
                    item.technique_id,

                "technique_name":
                    item.technique_name,

                "tactic":
                    item.tactic,

                "ml_score":
                    item.ml_score,

                "semantic_score":
                    item.semantic_score,

                "evidence_score":
                    item.evidence_score,

                "final_score":
                    item.final_score,

                "evidence":
                    item.evidence,

                "context":
                    item.context,

                "status":
                    item.status,

                "explanation":
                    item.explanation
            }

            for item in results
        ]
    }