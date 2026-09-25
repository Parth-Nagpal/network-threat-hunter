import datetime
import os
import sys

# To interact with the database directly for setting up test data, we can import models if we have PYTHONPATH set,
# or we can just use the API. Since there is no API to insert arbitrary events, we will interact with the DB directly.

from database import SessionLocal, engine
import models
import schemas
from detection.scanner import detect_port_scan, detect_network_sweep, detect_ssh_brute_force, detect_dns_anomaly, detect_beaconing

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


def test_ssh_normal_traffic(db):
    print("Testing SSH brute force – normal traffic...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Only 3 failed SSH attempts – below threshold of 5
    for i in range(3):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.10.10.1",
            src_port=40000 + i,
            dst_ip="10.10.10.50",
            dst_port=22,
            protocol="tcp",
            connection_state="REJ",
        )
        db.add(event)
    db.commit()

    alerts = detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
    assert alerts == 0, f"Expected 0 alerts, got {alerts}"
    print("SSH normal traffic test passed.")


def test_ssh_brute_force(db):
    print("Testing SSH brute force detection...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # 8 failed SSH attempts – above threshold of 5
    for i in range(8):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.20.20.1",
            src_port=50000 + i,
            dst_ip="10.20.20.100",
            dst_port=22,
            protocol="tcp",
            connection_state="REJ",
        )
        db.add(event)
    db.commit()

    alerts = detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "SSH Brute Force Detected"
    ).first()
    assert alert is not None
    assert alert.src_ip == "10.20.20.1"
    assert alert.dst_ip == "10.20.20.100"
    import json
    ev = json.loads(alert.evidence)
    assert ev["failed_attempts"] >= 5
    assert ev["successful_login"] is False
    print("SSH brute force test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


def test_ssh_brute_force_with_success(db):
    print("Testing SSH brute force with subsequent successful login...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # 6 failed attempts followed by 1 successful login
    for i in range(6):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.30.30.1",
            src_port=55000 + i,
            dst_ip="10.30.30.200",
            dst_port=22,
            protocol="tcp",
            connection_state="S0",
        )
        db.add(event)
    # Successful SSH login after failures
    success_event = models.ConnectionEvent(
        timestamp=now + datetime.timedelta(seconds=7),
        src_ip="10.30.30.1",
        src_port=55100,
        dst_ip="10.30.30.200",
        dst_port=22,
        protocol="tcp",
        connection_state="SF",
    )
    db.add(success_event)
    db.commit()

    alerts = detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "SSH Brute Force Detected"
    ).first()
    import json
    ev = json.loads(alert.evidence)
    assert ev["successful_login"] is True
    assert len(ev["success_timestamps"]) >= 1
    print("SSH brute force + successful login test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


def test_dns_normal_traffic(db):
    print("Testing DNS anomaly – normal traffic...")
    db.query(models.DNSEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # 10 short, infrequent DNS queries – well below both thresholds
    for i in range(10):
        event = models.DNSEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="192.168.10.1",
            dst_dns_server="8.8.8.8",
            queried_domain=f"example{i}.com",
            query_type="A",
        )
        db.add(event)
    db.commit()

    alerts = detect_dns_anomaly(db, time_window_seconds=60, query_count_threshold=100, max_query_length=50)
    assert alerts == 0, f"Expected 0 alerts, got {alerts}"
    print("DNS normal traffic test passed.")


def test_dns_high_frequency(db):
    print("Testing DNS anomaly – high query frequency...")
    db.query(models.DNSEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # 120 DNS queries within 60 seconds – above frequency threshold of 100
    for i in range(120):
        event = models.DNSEvent(
            timestamp=now + datetime.timedelta(seconds=i % 59),
            src_ip="10.50.50.1",
            dst_dns_server="8.8.8.8",
            queried_domain=f"normal{i}.com",
            query_type="A",
        )
        db.add(event)
    db.commit()

    alerts = detect_dns_anomaly(db, time_window_seconds=60, query_count_threshold=100, max_query_length=50)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "DNS Anomaly Detected"
    ).first()
    assert alert is not None
    assert alert.src_ip == "10.50.50.1"
    import json
    ev = json.loads(alert.evidence)
    assert ev["high_frequency"] is True
    assert ev["query_count"] >= 100
    print("DNS high-frequency test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


def test_dns_long_query(db):
    print("Testing DNS anomaly – long query name...")
    db.query(models.DNSEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # A small number of queries but one has a suspiciously long domain (DNS tunnel / DGA)
    normal_domains = [f"legit{i}.com" for i in range(5)]
    tunnel_domain = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBkbnMgdHVubmVsIHF1ZXJ5".ljust(70, "x") + ".evil.com"
    all_domains = normal_domains + [tunnel_domain]

    for i, domain in enumerate(all_domains):
        event = models.DNSEvent(
            timestamp=now + datetime.timedelta(seconds=i),
            src_ip="10.60.60.1",
            dst_dns_server="8.8.8.8",
            queried_domain=domain,
            query_type="TXT",
        )
        db.add(event)
    db.commit()

    alerts = detect_dns_anomaly(db, time_window_seconds=60, query_count_threshold=100, max_query_length=50)
    assert alerts == 1, f"Expected 1 alert, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "DNS Anomaly Detected"
    ).first()
    import json
    ev = json.loads(alert.evidence)
    assert ev["max_query_length"] > 50
    assert len(ev["long_domains_sample"]) >= 1
    assert ev["high_frequency"] is False
    print("DNS long-query test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


def test_beaconing_normal_traffic(db):
    print("Testing beaconing – irregular (normal) traffic...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Highly irregular intervals: 1s, 30s, 5s, 120s, 2s — CoV will be very high
    offsets = [0, 1, 31, 36, 156, 158]
    for i, secs in enumerate(offsets):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=secs),
            src_ip="172.16.1.1",
            src_port=30000 + i,
            dst_ip="1.2.3.4",
            dst_port=443,
            protocol="tcp",
            connection_state="SF",
        )
        db.add(event)
    db.commit()

    alerts = detect_beaconing(db, time_window_seconds=3600, min_connections=5, max_jitter_cov=0.25)
    assert alerts == 0, f"Expected 0 alerts for irregular traffic, got {alerts}"
    print("Beaconing normal traffic test passed.")


def test_beaconing_detection(db):
    print("Testing beaconing – periodic beacon traffic...")
    db.query(models.ConnectionEvent).delete()
    db.query(models.Alert).delete()
    db.commit()

    now = datetime.datetime.utcnow()
    # Very regular: every 60s ± 2s (CoV ≪ 0.25)
    base_interval = 60
    import random; random.seed(42)
    offsets = [0]
    for _ in range(7):
        offsets.append(offsets[-1] + base_interval + random.uniform(-1, 1))

    for i, secs in enumerate(offsets):
        event = models.ConnectionEvent(
            timestamp=now + datetime.timedelta(seconds=secs),
            src_ip="10.99.99.1",
            src_port=40000 + i,
            dst_ip="203.0.113.5",
            dst_port=443,
            protocol="tcp",
            connection_state="SF",
        )
        db.add(event)
    db.commit()

    alerts = detect_beaconing(db, time_window_seconds=3600, min_connections=5, max_jitter_cov=0.25)
    assert alerts == 1, f"Expected 1 alert for beacon traffic, got {alerts}"

    alert = db.query(models.Alert).filter(
        models.Alert.rule_name == "Beaconing Detected"
    ).first()
    assert alert is not None
    assert alert.src_ip == "10.99.99.1"
    assert alert.dst_ip == "203.0.113.5"
    import json
    ev = json.loads(alert.evidence)
    assert ev["connection_count"] >= 5
    assert ev["interval_cov"] <= 0.25
    assert ev["avg_interval_seconds"] > 0
    print("Beaconing detection test passed. Alert generated:")
    print(alert.description)
    print("Evidence:", alert.evidence)


if __name__ == "__main__":
    db = setup_db()
    try:
        test_normal_traffic(db)
        test_port_scan_traffic(db)
        test_sweep_normal_traffic(db)
        test_sweep_detection(db)
        test_ssh_normal_traffic(db)
        test_ssh_brute_force(db)
        test_ssh_brute_force_with_success(db)
        test_dns_normal_traffic(db)
        test_dns_high_frequency(db)
        test_dns_long_query(db)
        test_beaconing_normal_traffic(db)
        test_beaconing_detection(db)
    finally:
        db.close()
