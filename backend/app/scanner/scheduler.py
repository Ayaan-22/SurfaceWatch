from datetime import datetime, timedelta, timezone


def next_run(scan_frequency: str, from_time: datetime | None = None) -> datetime | None:
    base = from_time or datetime.now(timezone.utc)
    if scan_frequency == "daily":
        return base + timedelta(days=1)
    if scan_frequency == "weekly":
        return base + timedelta(weeks=1)
    if scan_frequency == "monthly":
        return base + timedelta(days=30)
    return None
