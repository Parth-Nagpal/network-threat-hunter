from datetime import timedelta

from sqlalchemy.orm import Session

import models


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def correlate_open_alerts(db: Session, window_minutes: int = 10) -> list[models.Incident]:
    """Create deterministic incidents from unassigned open alerts in time windows.

    Alerts are ordered by source, timestamp, and ID. Each group is anchored to
    its earliest alert, so every member falls within the configured window.
    Existing incident associations are left intact and excluded from new groups.
    """
    linked_alert_ids = db.query(models.IncidentAlert.alert_id).subquery()
    alerts = (
        db.query(models.Alert)
        .filter(
            models.Alert.status == "open",
            models.Alert.timestamp.isnot(None),
            ~models.Alert.id.in_(linked_alert_ids),
        )
        .order_by(models.Alert.src_ip, models.Alert.timestamp, models.Alert.id)
        .all()
    )

    grouped_by_source = {}
    for alert in alerts:
        grouped_by_source.setdefault(alert.src_ip, []).append(alert)

    window = timedelta(minutes=window_minutes)
    created = []
    for source_ip in sorted(grouped_by_source, key=lambda value: value or ""):
        source_alerts = grouped_by_source[source_ip]
        start = 0
        while start < len(source_alerts):
            anchor = source_alerts[start].timestamp
            end = start + 1
            while end < len(source_alerts) and source_alerts[end].timestamp - anchor <= window:
                end += 1
            group = source_alerts[start:end]
            if len(group) > 1:
                alert_ids = sorted(alert.id for alert in group)
                existing_sets = _existing_alert_sets(db)
                if tuple(alert_ids) not in existing_sets:
                    severity = max(
                        (alert.severity for alert in group),
                        key=lambda value: SEVERITY_RANK.get(value, 1),
                    )
                    incident = models.Incident(
                        title=f"Related alerts from {source_ip or 'unknown source'}",
                        summary=(
                            f"{len(group)} open alerts from source {source_ip or 'unknown'} "
                            f"occurred within {window_minutes} minutes."
                        ),
                        severity=severity,
                        status="open",
                    )
                    db.add(incident)
                    db.flush()
                    db.add_all([
                        models.IncidentAlert(incident_id=incident.id, alert_id=alert_id)
                        for alert_id in alert_ids
                    ])
                    created.append(incident)
            start = end

    if created:
        db.commit()
        for incident in created:
            db.refresh(incident)
    return created


def _existing_alert_sets(db: Session) -> set[tuple[int, ...]]:
    incidents = db.query(models.Incident).all()
    return {
        tuple(sorted(link.alert_id for link in incident.alert_links))
        for incident in incidents
    }
