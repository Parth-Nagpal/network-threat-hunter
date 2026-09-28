"""Safe synthetic Attack Lab workflow tests."""
from datetime import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from fastapi.testclient import TestClient

import models
from database import SessionLocal
from main import app


@pytest.fixture
def lab_client():
    return TestClient(app)


@pytest.fixture
def run_and_cleanup():
    run_ids = []
    yield run_ids
    db = SessionLocal()
    try:
        for run_id in run_ids:
            run = db.get(models.LabRun, run_id)
            if run is None:
                continue
            event_links = list(run.telemetry_links)
            alert_ids = [link.alert_id for link in run.alert_links]
            incident_ids = [link.incident_id for link in run.incident_links]
            db.query(models.IncidentAlert).filter(models.IncidentAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False) if alert_ids else None
            db.query(models.IncidentTechnique).filter(models.IncidentTechnique.incident_id.in_(incident_ids)).delete(synchronize_session=False) if incident_ids else None
            db.query(models.IncidentNote).filter(models.IncidentNote.incident_id.in_(incident_ids)).delete(synchronize_session=False) if incident_ids else None
            db.query(models.InvestigationAction).filter(models.InvestigationAction.incident_id.in_(incident_ids)).delete(synchronize_session=False) if incident_ids else None
            db.delete(run)
            db.flush()
            for link in event_links:
                event_model = {
                    "connection": models.ConnectionEvent,
                    "dns": models.DNSEvent,
                    "http": models.HTTPEvent,
                    "tls": models.SSLEvent,
                }[link.event_type]
                db.query(event_model).filter(event_model.id == link.event_id).delete(synchronize_session=False)
            if alert_ids:
                db.query(models.Alert).filter(models.Alert.id.in_(alert_ids)).delete(synchronize_session=False)
            if incident_ids:
                db.query(models.Incident).filter(models.Incident.id.in_(incident_ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_lab_lists_safe_scenarios(lab_client):
    response = lab_client.get("/api/lab/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert {item["id"] for item in scenarios} == {
        "port-scan", "network-sweep", "ssh-brute-force", "beaconing",
        "rare-destination", "minor-dns-anomaly", "dns-burst", "http-anomaly",
        "service-probing", "lateral-movement", "large-outbound-transfer", "multi-stage-attack",
    }
    assert all("synthetic" in item["safety"].lower() for item in scenarios)


@pytest.mark.parametrize("scenario_id,rule_name,severity", [
    ("port-scan", "Port Scan Detected", "high"),
    ("network-sweep", "Network Sweep Detected", "high"),
    ("ssh-brute-force", "SSH Brute Force Detected", "high"),
    ("beaconing", "Beaconing Detected", "medium"),
])
def test_scenario_runs_detection_and_records_workflow(lab_client, run_and_cleanup, scenario_id, rule_name, severity):
    response = lab_client.post(f"/api/lab/scenarios/{scenario_id}/run")
    assert response.status_code == 200
    run = response.json()
    run_and_cleanup.append(run["id"])
    assert run["status"] == "completed"
    assert run["end_time"]
    assert run["generated_event_count"] > 0
    assert run["generated_event_count"] == len(run["generated_telemetry"])
    assert all(event["is_simulated"] for event in run["generated_telemetry"])
    assert run["alerts"] and all(alert["rule_name"] == rule_name for alert in run["alerts"])
    assert all(alert["severity"] == severity for alert in run["alerts"])
    assert run["incident_ids"] and run["incidents"]
    assert set(run["alert_ids"]).issubset({alert["id"] for alert in run["alerts"]})

    listed = lab_client.get("/api/lab/runs")
    assert listed.status_code == 200
    assert any(item["id"] == run["id"] for item in listed.json())
    detail = lab_client.get(f"/api/lab/runs/{run['id']}")
    assert detail.status_code == 200
    assert detail.json()["alert_ids"] == run["alert_ids"]
    assert detail.json()["incident_ids"] == run["incident_ids"]


@pytest.mark.parametrize("scenario_id,expected_severity", [
    ("rare-destination", "low"),
    ("minor-dns-anomaly", "low"),
    ("dns-burst", "medium"),
    ("http-anomaly", "medium"),
    ("service-probing", "high"),
    ("lateral-movement", "high"),
    ("large-outbound-transfer", "critical"),
    ("multi-stage-attack", "critical"),
])
def test_new_scenarios_detect_behavior_at_expected_severity(lab_client, run_and_cleanup, scenario_id, expected_severity):
    response = lab_client.post(f"/api/lab/scenarios/{scenario_id}/run")
    assert response.status_code == 200
    run = response.json()
    run_and_cleanup.append(run["id"])
    assert run["status"] == "completed"
    assert run["generated_event_count"] == len(run["generated_telemetry"]) > 0
    assert run["alerts"]
    assert expected_severity in {alert["severity"] for alert in run["alerts"]}
    if scenario_id == "multi-stage-attack":
        assert run["incident_ids"]
    assert all(event["is_simulated"] for event in run["generated_telemetry"])
    if scenario_id == "multi-stage-attack":
        chain = next(alert for alert in run["alerts"] if alert["rule_name"] == "Multi-Stage Attack Chain Detected")
        assert [item["stage"] for item in json.loads(chain["evidence"])["stages"]] == [
            "port_scan", "ssh_brute_force", "suspicious_communication",
        ]


def test_unknown_scenario_and_run_return_not_found(lab_client):
    assert lab_client.post("/api/lab/scenarios/arbitrary-target/run").status_code == 404
    assert lab_client.get("/api/lab/runs/999999999").status_code == 404
