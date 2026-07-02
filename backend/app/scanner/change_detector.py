def describe_change(change_type: str, old_value: str | None, new_value: str | None) -> dict[str, str | None]:
    severity = "info"
    if change_type in {"new_open_port", "security_header_removed", "risk_score_increased"}:
        severity = "medium"
    if change_type in {"public_database_port", "new_critical_finding"}:
        severity = "high"
    return {"change_type": change_type, "old_value": old_value, "new_value": new_value, "severity": severity}
