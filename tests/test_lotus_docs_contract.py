from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOTUS = ROOT / "docs" / "LOTUS.md"
PR_TEMPLATE = ROOT / ".github" / "pull_request_template.md"


def test_pr_evidence_is_bound_to_exact_head() -> None:
    template = PR_TEMPLATE.read_text(encoding="utf-8")

    assert "Exact PR head SHA validated" in template
    assert "Validation command" in template
    assert "Validation was run or rerun after the most recent head change" in template
    assert "Evidence becomes stale" in template
    assert "when the PR head changes" in template


def test_supersession_requires_identity_scope_and_review() -> None:
    text = LOTUS.read_text(encoding="utf-8")

    required_english = (
        "same canonical memory identity",
        "compatible source",
        "repository scope",
        "recorded as a conflict",
        "cannot silently replace",
    )
    for phrase in required_english:
        assert phrase in text

    assert "repository B / same topic but different identity or scope" in text
    assert "may not silently supersede" in text


def test_english_and_russian_contracts_keep_core_acceptance_boundaries() -> None:
    text = LOTUS.read_text(encoding="utf-8")
    english, russian = text.split("# Слой Лотоса CML", maxsplit=1)

    english_terms = (
        "bounded evidence",
        "schema validation",
        "canonical identity",
        "explicit review",
        "source, scope, state, and time",
        "supersede",
        "reject",
    )
    for term in english_terms:
        assert term in english

    russian_terms = (
        "ограниченного набора доказательств",
        "проверки схемы",
        "канонической идентичности",
        "явного review",
        "источнику, scope, состоянию и времени",
        "заменить",
        "отклонить",
    )
    for term in russian_terms:
        assert term in russian


def test_english_and_russian_contracts_keep_the_no_authority_boundary() -> None:
    text = LOTUS.read_text(encoding="utf-8")
    english, russian = text.split("# Слой Лотоса CML", maxsplit=1)

    assert "has no ownership, approval, execution, delivery, or merge authority" in english
    assert "не имеет права собственности" in russian
    assert "одобрения" in russian
    assert "исполнения" in russian
    assert "доставки или merge" in russian
    assert "не скрытый policy engine" in russian
