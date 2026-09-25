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
def investigation_case(db):
    now = datetime.utcnow()
    incident = models.Incident(
        title="Investigation fixture", summary="Phase 7 test", severity="high", status="investigating",
    )
    alert = models.Alert(
        timestamp=now - timedelta(minutes=1), rule_name="Port Scan Detected",
        src_ip="198.18.7.10", dst_ip="203.0.113.77", description="Test scan",
        evidence='{"destination_port": 443, "long_domains_sample": ["alert.example.test"]}',
    )
    events = [
        models.ConnectionEvent(timestamp=now, src_ip="198.18.7.10", src_port=42001,
                               dst_ip="203.0.113.77", dst_port=8443, protocol="tcp",
                               connection_state="SF"),
        models.DNSEvent(timestamp=now - timedelta(seconds=30), src_ip="203.0.113.77",
                        dst_dns_server="198.18.7.10", queried_domain="dns.example.test",
                        query_type="A"),
        models.HTTPEvent(timestamp=now - timedelta(seconds=20), src_ip="198.18.7.10",
                         dst_ip="203.0.113.78", method="GET", host="web.example.test",
                         uri="https://web.example.test/login"),
        models.SSLEvent(timestamp=now - timedelta(seconds=10), src_ip="203.0.113.77",
                        dst_ip="198.18.7.10", server_name="tls.example.test", version="TLSv1.3"),
        models.ConnectionEvent(timestamp=now + timedelta(minutes=20), src_ip="198.18.7.10",
                               src_port=42002, dst_ip="203.0.113.79", dst_port=22,
                               protocol="tcp", connection_state="SF"),
    ]
    db.add_all([incident, alert, *events])
    db.commit()
    db.refresh(incident)
    db.refresh(alert)
    db.add(models.IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.commit()
    yield incident, alert, events
    db.query(models.IncidentNote).filter_by(incident_id=incident.id).delete(synchronize_session=False)
    db.query(models.InvestigationAction).filter_by(incident_id=incident.id).delete(synchronize_session=False)
    db.query(models.IncidentAlert).filter_by(incident_id=incident.id).delete(synchronize_session=False)
    db.query(models.Alert).filter_by(id=alert.id).delete(synchronize_session=False)
    db.query(models.ConnectionEvent).filter(models.ConnectionEvent.id.in_(
        [event.id for event in events if isinstance(event, models.ConnectionEvent)]
    )).delete(synchronize_session=False)
    db.query(models.DNSEvent).filter(models.DNSEvent.id == events[1].id).delete(synchronize_session=False)
    db.query(models.HTTPEvent).filter(models.HTTPEvent.id == events[2].id).delete(synchronize_session=False)
    db.query(models.SSLEvent).filter(models.SSLEvent.id == events[3].id).delete(synchronize_session=False)
    db.delete(incident)
    db.commit()


def test_investigation_endpoint_returns_incident_alerts_and_timeline(client, investigation_case):
    incident, alert, _ = investigation_case
    response = client.get(f"/api/incidents/{incident.id}/investigation")
    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == incident.id
    assert payload["alerts"][0]["id"] == alert.id
    assert payload["timeline"][0]["rule_name"] == "Port Scan Detected"
    assert payload["notes"] == []
    assert payload["actions"] == []


def test_related_telemetry_pivots_on_alert_ips_and_time_window(client, investigation_case):
    incident, _, _ = investigation_case
    response = client.get(f"/api/incidents/{incident.id}/investigation", params={"window_minutes": 10})
    assert response.status_code == 200
    events = response.json()["related_telemetry"]
    assert {event["event_type"] for event in events} == {"connection", "dns", "http", "tls"}
    assert all("198.18.7.10" in {event["source_ip"], event["destination_ip"]} or
               "203.0.113.77" in {event["source_ip"], event["destination_ip"]} for event in events)
    timestamps = [event["timestamp"] for event in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_iocs_extracted_from_alerts_and_related_telemetry(client, investigation_case):
    incident, _, _ = investigation_case
    iocs = client.get(f"/api/incidents/{incident.id}/investigation").json()["iocs"]
    assert {"198.18.7.10", "203.0.113.77"} <= set(iocs["ip_addresses"])
    assert {"alert.example.test", "dns.example.test", "web.example.test", "tls.example.test"} <= set(iocs["domains"])
    assert "https://web.example.test/login" in iocs["urls"]
    assert {443, 8443} <= set(iocs["destination_ports"])


def test_add_and_list_analyst_notes(client, investigation_case):
    incident, _, _ = investigation_case
    response = client.post(f"/api/incidents/{incident.id}/notes", json={"content": "Reviewed packet evidence"})
    assert response.status_code == 200
    note_id = response.json()["id"]
    investigation = client.get(f"/api/incidents/{incident.id}/investigation").json()
    assert investigation["notes"][0]["id"] == note_id
    assert investigation["notes"][0]["content"] == "Reviewed packet evidence"


def test_delete_analyst_note(client, investigation_case):
    incident, _, _ = investigation_case
    note = client.post(f"/api/incidents/{incident.id}/notes", json={"content": "Remove me"}).json()
    response = client.delete(f"/api/incidents/{incident.id}/notes/{note['id']}")
    assert response.status_code == 200
    assert client.get(f"/api/incidents/{incident.id}/investigation").json()["notes"] == []


def test_add_and_list_investigation_actions(client, investigation_case):
    incident, _, _ = investigation_case
    response = client.post(f"/api/incidents/{incident.id}/actions", json={
        "action_type": "marked_suspicious", "comment": "Matches scan behavior",
    })
    assert response.status_code == 200
    action_id = response.json()["id"]
    investigation = client.get(f"/api/incidents/{incident.id}/investigation").json()
    assert investigation["actions"][0]["id"] == action_id
    assert investigation["actions"][0]["action_type"] == "marked_suspicious"
    assert client.post(f"/api/incidents/{incident.id}/actions", json={"action_type": "unknown"}).status_code == 422


def test_investigation_returns_404_for_missing_incident(client):
    assert client.get("/api/incidents/999999/investigation").status_code == 404
    assert client.post("/api/incidents/999999/notes", json={"content": "note"}).status_code == 404
    assert client.post("/api/incidents/999999/actions", json={"action_type": "reviewed"}).status_code == 404
    assert client.delete("/api/incidents/999999/notes/1").status_code == 404


def test_investigation_does_not_modify_alert_evidence(client, investigation_case):
    incident, alert, _ = investigation_case
    before = alert.evidence
    response = client.get(f"/api/incidents/{incident.id}/investigation")
    assert response.status_code == 200
    assert response.json()["alerts"][0]["evidence"] == before
    assert alert.evidence == before
