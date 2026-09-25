import datetime
import os
import sys

# To interact with the database directly for setting up test data, we can import models if we have PYTHONPATH set,
# or we can just use the API. Since there is no API to insert arbitrary events, we will interact with the DB directly.

from database import SessionLocal, engine
import models
import schemas
from detection.scanner import detect_port_scan, detect_network_sweep

def setup_db():
    models.Base.metadata.create_all(bind=engine)
    return SessionLocal()

def test_normal_traffic(db):
    print("Testing normal traffic...")
    # Clear events and alerts
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Insert a few connections (less than threshold 10)
    for i in range(5):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="192.168.1.10",
            src_port=10000+i,
            dst_ip="10.0.0.5",
            dst_port=80+i,
            protocol="tcp",
            connection_state="S0"
        )
        db.add(event)
    db.commit()

    alerts = detect_port_scan(db, time_window_seconds=60, threshold=10)
    assert alerts == 0, f"Expected 0 alerts, got {alerts}"
    print("Normal traffic test passed.")

def test_port_scan_traffic(db):
    print("Testing port scan traffic...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Insert port scan (more than threshold 10 distinct ports)
    for i in range(15):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="192.168.1.100",
            src_port=20000+i,
            dst_ip="10.0.0.20",
            dst_port=1000+i, # Distinct ports
            protocol="tcp",
            connection_state="S0"
        )
        db.add(event)
    db.commit()

    alerts = detect_port_scan(db, time_window_seconds=60, threshold=10)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"
    
    # Check alert details
    alert = db.query(models.Alert).first()
    assert alert is not None
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "10.0.0.20"
    assert alert.rule_name == "Port Scan Detected"
    print("Port scan traffic test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)

def test_sweep_normal_traffic(db):
    print("Testing sweep – normal traffic...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Only 4 distinct destination IPs on port 80 – below threshold of 10
    for i in range(4):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.1.1.1",
            src_port=50000,
            dst_ip=f"172.16.0.{i+1}",
            dst_port=80,
            protocol="tcp",
            connection_state="S0"
        )
        db.add(event)
    db.commit()

    alerts = detect_network_sweep(db, time_window_seconds=60, threshold=10)
    assert alerts == 0, f"Expected 0 alerts, got {alerts}"
    print("Sweep normal traffic test passed.")


def test_sweep_detection(db):
    print("Testing network sweep detection...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # 15 distinct destination IPs all on port 445 – above threshold of 10
    for i in range(15):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.2.2.2",
            src_port=60000 + i,
            dst_ip=f"192.168.50.{i+1}",
            dst_port=445,
            protocol="tcp",
            connection_state="S0"
        )
        db.add(event)
    db.commit()

    alerts = detect_network_sweep(db, time_window_seconds=60, threshold=10)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "Network Sweep Detected"
    ).first()
    assert alert is not None
    assert alert.src_ip == "10.2.2.2"
    assert alert.dst_ip == "port:445"
    assert alert.rule_name == "Network Sweep Detected"
    import json
    ev = json.loads(alert.evidence)
    assert ev["ip_count"] >= 10
    assert ev["destination_port"] == 445
    print("Network sweep detection test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


if __name__ == "__main__":
    db = setup_db()
    try:
        test_normal_traffic(db)
        test_port_scan_traffic(db)
        test_sweep_normal_traffic(db)
        test_sweep_detection(db)
    finally:
        db.close()
