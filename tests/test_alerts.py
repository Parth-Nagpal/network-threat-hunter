"""Focused API coverage for Phase 4 alert management."""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from database import SessionLocal
import models
from main import app


class AlertApiTests(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.alerts = [
            models.Alert(timestamp=datetime.utcnow(),
                         rule_name="Port Scan Detected", src_ip="198.51.100.251", dst_ip="192.0.2.2",
                         description="Observed scan", evidence='{"port_count": 12}',
                         status="open", severity="phase4_test_high"),
            models.Alert(timestamp=datetime.utcnow(),
                         rule_name="DNS Anomaly Detected", src_ip="198.51.100.252", dst_ip="dns",
                         description="Observed DNS anomaly", evidence='{"query_count": 120}',
                         status="phase4_test_investigating", severity="phase4_test_medium"),
        ]
        self.db.add_all(self.alerts)
        self.db.commit()
        self.db.refresh(self.alerts[0])
        self.db.refresh(self.alerts[1])
        self.client = TestClient(app)

    def tearDown(self):
        for alert in self.alerts:
            self.db.delete(alert)
        self.db.commit()
        self.db.close()

    def test_list_and_filter_alerts(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()), 2)
        self.assertIn("created_at", response.json()[0])
        self.assertEqual(self.client.get("/api/alerts?severity=phase4_test_high").json()[0]["src_ip"], "198.51.100.251")
        self.assertEqual(self.client.get("/api/alerts?type=Port Scan").json()[0]["alert_type"], "Port Scan")
        self.assertEqual(self.client.get("/api/alerts?status=phase4_test_investigating").json()[0]["status"], "phase4_test_investigating")

    def test_view_alert_preserves_evidence_and_returns_404(self):
        response = self.client.get(f"/api/alerts/{self.alerts[0].id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["evidence"], '{"port_count": 12}')
        self.assertEqual(self.client.get("/api/alerts/999999").status_code, 404)

    def test_update_status(self):
        response = self.client.patch(f"/api/alerts/{self.alerts[0].id}/status", json={"status": "false_positive"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "false_positive")
        self.assertEqual(self.client.patch(f"/api/alerts/{self.alerts[0].id}/status", json={"status": "bad"}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
