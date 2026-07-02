from collections import Counter


SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}


def risk_level(score: int) -> str:
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def calculate_risk_score(severities: list[str]) -> tuple[int, str, dict[str, int]]:
    counts = Counter(severity.lower() for severity in severities)
    raw_score = sum(SEVERITY_POINTS.get(severity, 0) * count for severity, count in counts.items())
    normalized = min(100, raw_score)
    return normalized, risk_level(normalized), dict(counts)
