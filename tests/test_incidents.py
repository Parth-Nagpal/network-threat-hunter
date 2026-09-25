from datetime import datetime, timedelta
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from fastapi.testclient import TestClient

import models
from main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def incident_data(db):
    alerts = []
    incidents = []
    base_time = datetime(2025, 1, 1, 12, 0, 0)

    def make_alert(source_ip="198.51.100.201", minutes=0, severity="medium"):
        alert = models.Alert(
            timestamp=base_time + timedelta(minutes=minutes),
            rule_name="Port Scan Detected", src_ip=source_ip, dst_ip="203.0.113.201",
            description="Test alert", evidence='{"port_count": 11}', severity=severity,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alerts.append(alert)
        return alert

    def make_incident(**kwargs):
        kwargs.setdefault("title", "Test incident")
        kwargs.setdefault("summary", "Test summary")
        incident = models.Incident(**kwargs)
        db.add(incident)
        db.commit()
        db.refresh(incident)
        incidents.append(incident)
        return incident

    yield make_alert, make_incident

    alert_ids = [alert.id for alert in alerts]
    incident_ids = [incident.id for incident in incidents]
    if alert_ids or incident_ids:
        links_query = db.query(models.IncidentAlert)
        if alert_ids and incident_ids:
            links_query.filter(
                (models.IncidentAlert.alert_id.in_(alert_ids)) |
                (models.IncidentAlert.incident_id.in_(incident_ids))
            ).delete(synchronize_session=False)
        elif alert_ids:
            links_query.filter(models.IncidentAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        elif incident_ids:
            links_query.filter(models.IncidentAlert.incident_id.in_(incident_ids)).delete(synchronize_session=False)
        if incident_ids:
            db.query(models.Incident).filter(models.Incident.id.in_(incident_ids)).delete(synchronize_session=False)
        if alert_ids:
            db.query(models.Alert).filter(models.Alert.id.in_(alert_ids)).delete(synchronize_session=False)
        db.commit()
    db.query(models.Incident).filter(
        models.Incident.title == "Phase6 API-created cleanup"
    ).delete(synchronize_session=False)
    db.commit()


def test_incident_create_list_and_detail(client, incident_data):
    create = client.post("/api/incidents", json={
        "title": "Phase6 API-created cleanup", "summary": "Several scan alerts", "severity": "high",
    })
    assert create.status_code == 200
    incident_id = create.json()["id"]
    assert create.json()["status"] == "open"
    assert "updated_at" in create.json()
    listed = client.get("/api/incidents")
    assert listed.status_code == 200
    assert any(item["id"] == incident_id for item in listed.json())
    detail = client.get(f"/api/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["timeline"] == []


def test_incident_status_and_severity_update(client, incident_data):
    incident = incident_data[1](title="Update fields", summary="Before")
    response = client.patch(f"/api/incidents/{incident.id}", json={
        "status": "investigating", "severity": "critical", "summary": "Updated",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
    assert response.json()["severity"] == "critical"
    assert response.json()["summary"] == "Updated"
    assert client.patch(f"/api/incidents/{incident.id}", json={"status": "invalid"}).status_code == 422


def test_add_remove_alerts_and_chronological_timeline(client, db, incident_data):
    make_alert, make_incident = incident_data
    incident = make_incident(title="Timeline", summary="")
    later = make_alert(minutes=5)
    earlier = make_alert(minutes=1)
    assert client.post(f"/api/incidents/{incident.id}/alerts/{later.id}").status_code == 200
    added = client.post(f"/api/incidents/{incident.id}/alerts/{earlier.id}")
    assert added.status_code == 200
    assert [item["id"] for item in added.json()["alerts"]] == [earlier.id, later.id]
    assert added.json()["timeline"][0]["evidence"] == '{"port_count": 11}'
    duplicate = client.post(f"/api/incidents/{incident.id}/alerts/{earlier.id}")
    assert len(duplicate.json()["alerts"]) == 2
    removed = client.delete(f"/api/incidents/{incident.id}/alerts/{later.id}")
    assert removed.status_code == 200
    assert removed.json()["status"] == "removed"
    assert [item["id"] for item in client.get(f"/api/incidents/{incident.id}").json()["alerts"]] == [earlier.id]


def test_correlates_same_source_alerts_within_default_window(client, incident_data):
    make_alert, _ = incident_data
    first = make_alert(minutes=0, severity="medium")
    second = make_alert(minutes=9, severity="high")
    outside = make_alert(minutes=30)
    response = client.post("/api/incidents/correlate")
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 1
    incident = response.json()["incidents"][0]
    assert incident["severity"] == "high"
    assert [item["id"] for item in incident["alerts"]] == [first.id, second.id]
    assert outside.id not in [item["id"] for item in incident["alerts"]]


def test_alerts_outside_window_are_not_correlated(client, incident_data):
    make_alert, _ = incident_data
    make_alert(minutes=0)
    make_alert(minutes=11)
    response = client.post("/api/incidents/correlate")
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 0


def test_different_sources_are_not_correlated(client, incident_data):
    make_alert, _ = incident_data
    make_alert(source_ip="198.51.100.211", minutes=0)
    make_alert(source_ip="198.51.100.212", minutes=1)
    response = client.post("/api/incidents/correlate")
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 0


def test_repeated_correlation_does_not_duplicate_incident(client, incident_data):
    make_alert, _ = incident_data
    make_alert(minutes=0)
    make_alert(minutes=2)
    first = client.post("/api/incidents/correlate").json()
    second = client.post("/api/incidents/correlate").json()
    assert first["incidents_created"] == 1
    assert second["incidents_created"] == 0
    assert len(client.get("/api/incidents").json()) >= 1
