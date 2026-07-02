from app.scanner.risk_engine import calculate_risk_score


def test_risk_score_caps_at_100() -> None:
    score, level, counts = calculate_risk_score(["critical"] * 10)
    assert score == 100
    assert level == "critical"
    assert counts["critical"] == 10


def test_risk_score_medium_band() -> None:
    score, level, _ = calculate_risk_score(["medium", "medium", "low"])
    assert score == 19
    assert level == "low"
