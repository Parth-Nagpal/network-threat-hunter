from datetime import datetime, timedelta
from io import BytesIO
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

import models
from main import app


@pytest.fixture
def report_client():
    return TestClient(app)


@pytest.fixture
def report_records(db):
    now = datetime.utcnow().replace(microsecond=0)
    alert = models.Alert(
        timestamp=now, rule_name="SSH Brute Force Detected", src_ip="192.0.2.70",
        dst_ip="192.0.2.10", description="Repeated failed SSH connections",
        evidence='{"failed_attempts": 9}', status="investigating", severity="high",
    )
    other_alert = models.Alert(
        timestamp=now - timedelta(minutes=2), rule_name="Port Scan Detected",
        src_ip="192.0.2.71", dst_ip="192.0.2.10", description="Service scan",
        evidence='{"ports": [22, 80]}', severity="medium",
    )
    incident = models.Incident(
        title="Report test incident", summary="SSH password guessing activity",
        severity="high", status="investigating",
    )
    db.add_all([alert, other_alert, incident])
    db.flush()
    db.add(models.IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.add(models.IncidentNote(incident_id=incident.id, content="Validated source with network team"))
    db.add(models.InvestigationAction(incident_id=incident.id, action_type="reviewed", comment="Escalation reviewed"))
    technique = db.query(models.MitreTechnique).filter_by(technique_id="T1110").first()
    if technique:
        db.add(models.IncidentTechnique(incident_id=incident.id, technique_id=technique.technique_id))
    db.commit()
    db.refresh(alert); db.refresh(other_alert); db.refresh(incident)
    yield alert, other_alert, incident
    db.delete(incident)
    db.delete(alert)
    db.delete(other_alert)
    db.commit()


def test_alert_report_filters_records_and_exports_pdf_docx(report_client, report_records):
    alert, other_alert, _ = report_records
    payload = {
        "report_type": "alerts", "alert_ids": [alert.id, other_alert.id],
        "severity": "high", "status": "investigating",
    }
    preview = report_client.post("/api/reports/preview", json=payload)
    assert preview.status_code == 200
    data = preview.json()
    assert data["record_count"] == 1
    assert data["summary"] == "1 alert matches the selected records and filters."
    assert [item["id"] for item in data["alerts"]] == [alert.id]
    assert data["severity_breakdown"]["high"] == 1
    assert data["alert_types"]["SSH Brute Force"] == 1
    assert data["alerts"][0]["evidence"] == '{"failed_attempts": 9}'

    pdf = report_client.post("/api/reports/export/pdf", json=payload)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")
    assert "filename=\"ThreatHunter_Alerts_" in pdf.headers["content-disposition"]

    docx = report_client.post("/api/reports/export/docx", json=payload)
    assert docx.status_code == 200
    assert docx.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument")
    with ZipFile(BytesIO(docx.content)) as word_file:
        document_xml = word_file.read("word/document.xml").decode("utf-8")
        assert "SSH Brute Force Detected" in document_xml
        assert "failed_attempts" in document_xml


def test_incident_report_includes_investigation_evidence_and_mitre(report_client, report_records):
    alert, _, incident = report_records
    payload = {"report_type": "incidents", "incident_ids": [incident.id]}
    preview = report_client.post("/api/reports/preview", json=payload)
    assert preview.status_code == 200
    data = preview.json()
    assert data["record_count"] == 1
    result = data["incidents"][0]
    assert data["summary"] == "1 incident matches the selected records and filters."
    assert result["id"] == incident.id
    assert result["alerts"][0]["id"] == alert.id
    assert result["alerts"][0]["status"] == "investigating"
    assert result["timeline"][0]["source_ip"] == "192.0.2.70"
    assert result["notes"][0]["content"] == "Validated source with network team"
    assert result["actions"][0]["action_type"] == "reviewed"
    assert result["iocs"]["ip_addresses"]
    if result["mitre_techniques"]:
        assert result["mitre_techniques"][0]["technique_id"] == "T1110"

    docx = report_client.post("/api/reports/export/docx", json=payload)
    assert docx.status_code == 200
    with ZipFile(BytesIO(docx.content)) as word_file:
        document_xml = word_file.read("word/document.xml").decode("utf-8")
        assert "Chronological alert timeline" in document_xml
        assert "Indicators of compromise" in document_xml
        assert "Validated source with network team" in document_xml

    pdf = report_client.post("/api/reports/export/pdf", json=payload)
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")


def test_report_validation_and_format_errors(report_client):
    assert report_client.post("/api/reports/preview", json={"report_type": "alerts", "timestamp_from": "2025-01-02T00:00:00", "timestamp_to": "2025-01-01T00:00:00"}).status_code == 422
    assert report_client.post("/api/reports/export/csv", json={"report_type": "alerts"}).status_code == 400
