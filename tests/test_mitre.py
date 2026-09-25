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
def mapped_incident(db):
    incident = models.Incident(title="MITRE mapping fixture", summary="", severity="medium")
    rules = [
        "Port Scan Detected", "Network Sweep Detected", "SSH Brute Force Detected",
        "DNS Anomaly Detected", "Beaconing Detected",
    ]
    alerts = [
        models.Alert(timestamp=datetime.utcnow() + timedelta(seconds=index), rule_name=rule,
                     src_ip=f"198.18.8.{index + 1}", dst_ip="203.0.113.80",
                     description=rule, evidence="{}")
        for index, rule in enumerate(rules)
    ]
    db.add_all([incident, *alerts])
    db.commit()
    db.refresh(incident)
    for alert in alerts:
        db.refresh(alert)
        db.add(models.IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.commit()
    yield incident, alerts
    db.query(models.IncidentAlert).filter_by(incident_id=incident.id).delete(synchronize_session=False)
    db.query(models.Alert).filter(models.Alert.id.in_([alert.id for alert in alerts])).delete(synchronize_session=False)
    db.delete(incident)
    db.commit()


@pytest.fixture
def empty_incident(db):
    incident = models.Incident(title="Manual technique fixture", summary="")
    db.add(incident)
    db.commit()
    db.refresh(incident)
    yield incident
    db.query(models.IncidentTechnique).filter_by(incident_id=incident.id).delete(synchronize_session=False)
    db.delete(incident)
    db.commit()


def test_list_mitre_techniques(client):
    response = client.get("/api/mitre/techniques")
    assert response.status_code == 200
    techniques = {item["technique_id"]: item for item in response.json()}
    assert techniques["T1046"]["name"] == "Network Service Scanning"
    assert techniques["T1046"]["tactic"] == "Discovery"
    assert techniques["T1110"]["name"] == "Brute Force"
    assert techniques["T1110"]["tactic"] == "Credential Access"


def test_detection_mapping_is_evidence_based(client, mapped_incident):
    incident, _ = mapped_incident
    response = client.get(f"/api/mitre/incidents/{incident.id}")
    assert response.status_code == 200
    techniques = {item["technique_id"] for item in response.json()["techniques"]}
    assert techniques == {"T1046", "T1110"}


def test_incident_technique_retrieval_and_investigation_include_mappings(client, mapped_incident):
    incident, _ = mapped_incident
    retrieved = client.get(f"/api/mitre/incidents/{incident.id}").json()
    investigation = client.get(f"/api/incidents/{incident.id}/investigation").json()
    assert {item["technique_id"] for item in retrieved["techniques"]} == {"T1046", "T1110"}
    assert {item["technique_id"] for item in investigation["mitre_techniques"]} == {"T1046", "T1110"}


def test_manual_technique_association(client, empty_incident):
    response = client.post(f"/api/incidents/{empty_incident.id}/techniques/T1046")
    assert response.status_code == 200
    assert response.json()["techniques"][0]["technique_id"] == "T1046"


def test_duplicate_technique_association_is_idempotent(client, empty_incident):
    path = f"/api/incidents/{empty_incident.id}/techniques/T1110"
    assert client.post(path).status_code == 200
    duplicate = client.post(path)
    assert duplicate.status_code == 200
    assert [item["technique_id"] for item in duplicate.json()["techniques"]] == ["T1110"]


def test_remove_manual_technique_association(client, empty_incident):
    path = f"/api/incidents/{empty_incident.id}/techniques/T1046"
    client.post(path)
    removed = client.delete(path)
    assert removed.status_code == 200
    assert removed.json()["techniques"] == []


def test_unknown_incident_and_technique_handling(client, empty_incident):
    assert client.get("/api/mitre/incidents/999999").status_code == 404
    assert client.post("/api/incidents/999999/techniques/T1046").status_code == 404
    assert client.post(f"/api/incidents/{empty_incident.id}/techniques/T9999").status_code == 404
    assert client.delete(f"/api/incidents/{empty_incident.id}/techniques/T9999").status_code == 404
