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
def hunt_events(db):
    start = datetime.utcnow() - timedelta(minutes=4)
    rows = [
        models.ConnectionEvent(timestamp=start, src_ip="198.51.100.81", src_port=43001,
                               dst_ip="203.0.113.81", dst_port=443, protocol="tcp",
                               connection_state="SF"),
        models.ConnectionEvent(timestamp=start + timedelta(minutes=1), src_ip="198.51.100.81",
                               src_port=43002, dst_ip="203.0.113.82", dst_port=80,
                               protocol="tcp", connection_state="SF"),
        models.ConnectionEvent(timestamp=start + timedelta(minutes=2), src_ip="198.51.100.82",
                               src_port=53001, dst_ip="203.0.113.81", dst_port=53,
                               protocol="udp", connection_state="SF"),
        models.DNSEvent(timestamp=start + timedelta(minutes=3), src_ip="198.51.100.83",
                        dst_dns_server="203.0.113.53", queried_domain="sample.test",
                        query_type="A"),
        models.HTTPEvent(timestamp=start + timedelta(minutes=3, seconds=10), src_ip="198.51.100.84",
                         dst_ip="203.0.113.84", method="GET", host="sample.test", uri="/"),
        models.SSLEvent(timestamp=start + timedelta(minutes=3, seconds=20), src_ip="198.51.100.85",
                        dst_ip="203.0.113.85", server_name="sample.test", version="TLSv1.3"),
    ]
    db.add_all(rows)
    db.commit()
    for row in rows:
        db.refresh(row)
    yield rows
    for row in rows:
        db.delete(row)
    db.commit()


def test_hunt_without_filters_returns_normalized_newest_first(client, hunt_events):
    response = client.get("/api/hunt")
    assert response.status_code == 200
    events = response.json()
    assert events
    assert len(events) <= 100
    assert all({"event_type", "timestamp", "source_ip", "destination_ip", "protocol"} <= event.keys()
               for event in events)
    timestamps = [event["timestamp"] for event in events]
    assert timestamps == sorted(timestamps, reverse=True)
    assert {"connection", "dns", "http", "tls"} <= {event["event_type"] for event in events}


def test_hunt_filters_source_ip(client, hunt_events):
    response = client.get("/api/hunt", params={"source_ip": "198.51.100.81"})
    assert response.status_code == 200
    assert response.json()
    assert {event["source_ip"] for event in response.json()} == {"198.51.100.81"}


def test_hunt_filters_destination_ip_and_port(client, hunt_events):
    response = client.get("/api/hunt", params={
        "destination_ip": "203.0.113.81", "destination_port": 443,
    })
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["destination_ip"] == "203.0.113.81"
    assert response.json()[0]["destination_port"] == 443


def test_hunt_filters_protocol(client, hunt_events):
    response = client.get("/api/hunt", params={"protocol": "udp"})
    assert response.status_code == 200
    assert response.json()
    assert {event["protocol"] for event in response.json()} == {"udp"}


def test_hunt_filters_time_range(client, hunt_events):
    start = (datetime.utcnow() - timedelta(minutes=3, seconds=30)).isoformat()
    end = (datetime.utcnow() - timedelta(minutes=2, seconds=30)).isoformat()
    response = client.get("/api/hunt", params={"timestamp_from": start, "timestamp_to": end})
    assert response.status_code == 200
    assert response.json()
    assert all(start <= event["timestamp"] <= end for event in response.json())


def test_hunt_enforces_result_limit(client, hunt_events):
    response = client.get("/api/hunt", params={"source_ip": "198.51.100.81", "limit": 1})
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert client.get("/api/hunt", params={"limit": 501}).status_code == 422


def test_hunt_alert_evidence_returns_recorded_metadata(client, db):
    alert = models.Alert(timestamp=datetime.utcnow(), rule_name="Port Scan Detected",
                         src_ip="198.51.100.91", dst_ip="203.0.113.91",
                         description="Scan evidence available", evidence='{"port_count": 12}')
    db.add(alert)
    db.commit()
    db.refresh(alert)
    try:
        response = client.get(f"/api/hunt/alerts/{alert.id}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["evidence"] == '{"port_count": 12}'
        assert payload["evidence_metadata"] == {"port_count": 12}
        assert payload["source_ip"] == "198.51.100.91"
    finally:
        db.delete(alert)
        db.commit()
