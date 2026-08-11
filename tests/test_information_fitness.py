import json
from pathlib import Path

from cml.integrations.information_fitness import (
    InformationFitnessStatus,
    evaluate_information_fitness,
)
from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityResult,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
)
from cml.integrations.memory_applicability import (
    ApplicabilityResult,
    ApplicabilityStatus,
)


FIXTURE = Path(__file__).parent / "fixtures" / "information_fitness_v0.1.json"


def _quality(readiness: str, reasons: list[str]) -> InformationQualityResult:
    if readiness == "READY":
        truth = SemanticTruthStatus.SUPPORTED
        completeness = CompletenessStatus.COMPLETE
        relevance = RelevanceStatus.RELEVANT
    elif readiness == "EXCLUDE":
        truth = SemanticTruthStatus.CONTRADICTED
        completeness = CompletenessStatus.COMPLETE
        relevance = RelevanceStatus.RELEVANT
    else:
        truth = SemanticTruthStatus.UNRESOLVED
        completeness = CompletenessStatus.INCOMPLETE
        relevance = RelevanceStatus.RELEVANT

    return InformationQualityResult(
        semantic_truth=truth,
        completeness=completeness,
        relevance=relevance,
        readiness=QualityReadiness(readiness),
        reasons=tuple(reasons),
    )


def test_frozen_information_fitness_fixture() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    for case in data["cases"]:
        applicability = ApplicabilityResult(
            status=ApplicabilityStatus(case["applicability"]["status"]),
            reasons=tuple(case["applicability"]["reasons"]),
        )
        quality = _quality(
            case["quality"]["readiness"],
            case["quality"]["reasons"],
        )

        result = evaluate_information_fitness(
            applicability=applicability,
            quality=quality,
        )

        assert result.status is InformationFitnessStatus(case["expected_status"])
        assert list(result.reasons) == case["expected_reasons"]
        assert result.authorizes_action is False


def test_only_match_plus_ready_reaches_authority_check() -> None:
    result = evaluate_information_fitness(
        applicability=ApplicabilityResult(ApplicabilityStatus.MATCH, ()),
        quality=_quality("READY", []),
    )

    assert result.ready_for_authority_check is True
    assert result.authorizes_action is False


def test_blocking_applicability_precedes_quality_review() -> None:
    result = evaluate_information_fitness(
        applicability=ApplicabilityResult(
            ApplicabilityStatus.DRIFT,
            ("source_digest_mismatch",),
        ),
        quality=_quality("REVIEW", ["completeness_missing:approval"]),
    )

    assert result.status is InformationFitnessStatus.NOT_FIT
    assert result.reasons == (
        "applicability:source_digest_mismatch",
        "quality:completeness_missing:approval",
    )
