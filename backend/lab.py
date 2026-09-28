from datetime import datetime, timedelta

from sqlalchemy.orm import Session

import models
from correlation import correlate_open_alerts
from detection.scanner import (
    detect_beaconing,
    detect_network_sweep,
    detect_port_scan,
    detect_ssh_brute_force,
)
from detection.lab_scanner import (
    detect_http_anomaly,
    detect_large_outbound_transfer,
    detect_lateral_movement,
    detect_minor_dns_anomaly,
    detect_multistage_attack_chain,
    detect_rare_destination,
    detect_service_probing,
)


SCENARIOS = {
    "port-scan": {
        "id": "port-scan",
        "name": "Port Scan Simulation",
        "description": "Synthetic TCP connections probe 11 ports on each of two documentation-only target IPs.",
        "detection": "Port Scan Detected",
    },
    "network-sweep": {
        "id": "network-sweep",
        "name": "Network Sweep Simulation",
        "description": "Synthetic TCP connections contact 11 documentation-only host IPs on two ports.",
        "detection": "Network Sweep Detected",
    },
    "ssh-brute-force": {
        "id": "ssh-brute-force",
        "name": "SSH Brute Force Simulation",
        "description": "Synthetic failed SSH connection records exercise the existing brute-force detector; no credentials are sent.",
        "detection": "SSH Brute Force Detected",
    },
    "beaconing": {
        "id": "beaconing",
        "name": "Beaconing Simulation",
        "description": "Synthetic, evenly spaced connection records target two documentation-only IPs; no packets are sent.",
        "detection": "Beaconing Detected",
    },
    "rare-destination": {
        "id": "rare-destination", "name": "Rare Destination Simulation",
        "description": "Synthetic repeated connections to a common endpoint followed by one unusual destination.",
        "detection": "Rare Destination Detected",
    },
    "minor-dns-anomaly": {
        "id": "minor-dns-anomaly", "name": "Minor DNS Anomaly Simulation",
        "description": "Synthetic isolated DNS failure response, evaluated as a low-severity anomaly.",
        "detection": "Minor DNS Traffic Anomaly Detected",
    },
    "dns-burst": {
        "id": "dns-burst", "name": "DNS Burst Simulation",
        "description": "Synthetic short-window DNS query burst evaluated by the existing DNS anomaly detector.",
        "detection": "DNS Anomaly Detected",
    },
    "http-anomaly": {
        "id": "http-anomaly", "name": "HTTP Anomaly Simulation",
        "description": "Synthetic server-error HTTP request evaluated by the HTTP behavior detector.",
        "detection": "HTTP Anomaly Detected",
    },
    "service-probing": {
        "id": "service-probing", "name": "Service Probing Simulation",
        "description": "Synthetic probing of a small set of distinct services, below the port-scan threshold.",
        "detection": "Service Probing Detected",
    },
    "lateral-movement": {
        "id": "lateral-movement", "name": "Lateral Movement Simulation",
        "description": "Synthetic remote-access attempts between private-address telemetry hosts.",
        "detection": "Lateral Movement Detected",
    },
    "large-outbound-transfer": {
        "id": "large-outbound-transfer", "name": "Large Outbound Transfer Simulation",
        "description": "Synthetic connection telemetry with a large outbound byte count; no data is transmitted.",
        "detection": "Large Outbound Transfer Detected",
    },
    "multi-stage-attack": {
        "id": "multi-stage-attack", "name": "Multi-Stage Attack Chain Simulation",
        "description": "Synthetic scan, failed SSH attempts, then high-volume outbound connection telemetry.",
        "detection": "Multi-Stage Attack Chain Detected",
    },
}

EVENT_MODELS = {
    "connection": models.ConnectionEvent,
    "dns": models.DNSEvent,
    "http": models.HTTPEvent,
    "tls": models.SSLEvent,
}


def scenario_catalog():
    return [dict(scenario, safety="Synthetic localhost-database telemetry only; no network packets or credentials.")
            for scenario in SCENARIOS.values()]


def _synthetic_source_ip(run_id: int, private: bool = False) -> str:
    if private:
        return f"10.77.{(run_id // 254) % 254}.{run_id % 254 + 1}"
    # 198.18.0.0/16 is reserved for benchmarking; these records are never sent.
    offset = (run_id - 1) % (254 * 256)
    return f"198.18.{offset // 254}.{offset % 254 + 1}"


def _synthetic_target_ip(run_id: int, offset: int) -> str:
    # TEST-NET-3 documentation range; targets exist only as telemetry values.
    host = ((run_id + offset - 1) % 254) + 1
    return f"203.0.113.{host}"


def _make_events(scenario_id: str, source_ip: str, run_id: int, started_at: datetime):
    rows = []
    if scenario_id == "port-scan":
        for target_offset in (1, 2):
            target_ip = _synthetic_target_ip(run_id, target_offset)
            for index in range(11):
                rows.append(models.ConnectionEvent(
                    timestamp=started_at + timedelta(milliseconds=100 * len(rows)),
                    src_ip=source_ip, src_port=40000 + index, dst_ip=target_ip,
                    dst_port=2000 + index, protocol="tcp", connection_state="S0",
                ))
    elif scenario_id == "network-sweep":
        for destination_port in (80, 443):
            for host_offset in range(20, 31):
                rows.append(models.ConnectionEvent(
                    timestamp=started_at + timedelta(milliseconds=100 * len(rows)),
                    src_ip=source_ip, src_port=41000 + len(rows),
                    dst_ip=_synthetic_target_ip(run_id, host_offset),
                    dst_port=destination_port, protocol="tcp", connection_state="S0",
                ))
    elif scenario_id == "ssh-brute-force":
        for target_offset in (1, 2):
            target_ip = _synthetic_target_ip(run_id, target_offset)
            for index in range(6):
                rows.append(models.ConnectionEvent(
                    timestamp=started_at + timedelta(milliseconds=100 * len(rows)),
                    src_ip=source_ip, src_port=42000 + index, dst_ip=target_ip,
                    dst_port=22, protocol="tcp", connection_state="REJ",
                ))
    elif scenario_id == "beaconing":
        for target_offset in (1, 2):
            target_ip = _synthetic_target_ip(run_id, target_offset)
            for index in range(6):
                rows.append(models.ConnectionEvent(
                    timestamp=started_at + timedelta(milliseconds=500 * index),
                    src_ip=source_ip, src_port=43000 + index, dst_ip=target_ip,
                    dst_port=443, protocol="tcp", connection_state="SF",
                ))
    elif scenario_id == "rare-destination":
        common = _synthetic_target_ip(run_id, 40)
        for index in range(3):
            rows.append(models.ConnectionEvent(
                timestamp=started_at + timedelta(milliseconds=200 * index), src_ip=source_ip,
                src_port=44000 + index, dst_ip=common, dst_port=443, protocol="tcp", connection_state="SF",
            ))
        rows.append(models.ConnectionEvent(
            timestamp=started_at + timedelta(seconds=1), src_ip=source_ip, src_port=44003,
            dst_ip=_synthetic_target_ip(run_id, 41), dst_port=8443, protocol="tcp", connection_state="SF",
        ))
    elif scenario_id in {"minor-dns-anomaly", "dns-burst"}:
        count = 1 if scenario_id == "minor-dns-anomaly" else 12
        for index in range(count):
            rows.append(models.DNSEvent(
                timestamp=started_at + timedelta(milliseconds=index * 100), src_ip=source_ip,
                dst_dns_server="192.0.2.53", queried_domain=f"lab-{index}.example.test",
                query_type="A", response_code="NXDOMAIN" if scenario_id == "minor-dns-anomaly" else "NOERROR",
            ))
    elif scenario_id == "http-anomaly":
        rows.append(models.HTTPEvent(
            timestamp=started_at, src_ip=source_ip, dst_ip=_synthetic_target_ip(run_id, 50),
            method="GET", host="service.example.test", uri="/lab/status", status_code=503,
            user_agent="ThreatHunter-Synthetic-Lab",
        ))
    elif scenario_id == "service-probing":
        for index, port in enumerate((22, 80, 443, 8080)):
            rows.append(models.ConnectionEvent(
                timestamp=started_at + timedelta(milliseconds=200 * index), src_ip=source_ip,
                src_port=45000 + index, dst_ip=_synthetic_target_ip(run_id, 60), dst_port=port,
                protocol="tcp", connection_state="S0",
            ))
    elif scenario_id == "lateral-movement":
        for index, (offset, port) in enumerate(((1, 445), (2, 3389), (3, 22))):
            rows.append(models.ConnectionEvent(
                timestamp=started_at + timedelta(milliseconds=250 * index), src_ip=source_ip,
                src_port=46000 + index, dst_ip=f"10.78.0.{((run_id + offset - 1) % 254) + 1}",
                dst_port=port, protocol="tcp", connection_state="S0",
            ))
    elif scenario_id == "large-outbound-transfer":
        rows.append(models.ConnectionEvent(
            timestamp=started_at, src_ip=source_ip, src_port=47000,
            dst_ip=_synthetic_target_ip(run_id, 70), dst_port=443, protocol="tcp",
            connection_state="SF", bytes_sent=25_000_000, bytes_received=4096,
        ))
    elif scenario_id == "multi-stage-attack":
        target_ip = _synthetic_target_ip(run_id, 80)
        for index in range(11):
            rows.append(models.ConnectionEvent(
                timestamp=started_at + timedelta(milliseconds=index * 50), src_ip=source_ip,
                src_port=48000 + index, dst_ip=target_ip, dst_port=2000 + index,
                protocol="tcp", connection_state="S0",
            ))
        for index in range(6):
            rows.append(models.ConnectionEvent(
                timestamp=started_at + timedelta(seconds=2, milliseconds=index * 100), src_ip=source_ip,
                src_port=48100 + index, dst_ip=target_ip, dst_port=22,
                protocol="tcp", connection_state="REJ",
            ))
        rows.append(models.ConnectionEvent(
            timestamp=started_at + timedelta(seconds=4), src_ip=source_ip, src_port=48150,
            dst_ip=_synthetic_target_ip(run_id, 81), dst_port=443, protocol="tcp",
            connection_state="SF", bytes_sent=25_000_000, bytes_received=2048,
        ))
    return rows


def _event_type(event) -> str:
    if isinstance(event, models.ConnectionEvent):
        return "connection"
    if isinstance(event, models.DNSEvent):
        return "dns"
    if isinstance(event, models.HTTPEvent):
        return "http"
    return "tls"


def _run_detection(db: Session, scenario_id: str, source_ip: str) -> None:
    if scenario_id == "port-scan":
        detect_port_scan(db, time_window_seconds=60, threshold=10)
    elif scenario_id == "network-sweep":
        detect_network_sweep(db, time_window_seconds=60, threshold=10)
    elif scenario_id == "ssh-brute-force":
        detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
    elif scenario_id == "beaconing":
        detect_beaconing(db, time_window_seconds=3600, min_connections=5, max_jitter_cov=0.25)
    elif scenario_id == "rare-destination":
        detect_rare_destination(db, source_ip)
    elif scenario_id == "minor-dns-anomaly":
        detect_minor_dns_anomaly(db, source_ip)
    elif scenario_id == "dns-burst":
        from detection.scanner import detect_dns_anomaly
        detect_dns_anomaly(db, time_window_seconds=60, query_count_threshold=8, max_query_length=80)
    elif scenario_id == "http-anomaly":
        detect_http_anomaly(db, source_ip)
    elif scenario_id == "service-probing":
        detect_service_probing(db, source_ip)
    elif scenario_id == "lateral-movement":
        detect_lateral_movement(db, source_ip)
    elif scenario_id == "large-outbound-transfer":
        detect_large_outbound_transfer(db, source_ip)
    elif scenario_id == "multi-stage-attack":
        detect_port_scan(db, time_window_seconds=60, threshold=10)
        detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
        detect_large_outbound_transfer(db, source_ip)
        detect_multistage_attack_chain(db, source_ip)


def run_scenario(db: Session, scenario_id: str) -> models.LabRun | None:
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        return None
    run = models.LabRun(
        scenario_id=scenario_id,
        scenario_name=scenario["name"],
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    source_ip = _synthetic_source_ip(run.id, private=scenario_id == "lateral-movement")
    events = _make_events(scenario_id, source_ip, run.id, run.started_at)
    db.add_all(events)
    db.flush()
    db.add_all([
        models.LabRunTelemetry(run_id=run.id, event_type=_event_type(event), event_id=event.id)
        for event in events
    ])
    run.generated_event_count = len(events)
    db.commit()

    try:
        _run_detection(db, scenario_id, source_ip)
        alert_rows = db.query(models.Alert).filter(
            models.Alert.src_ip == source_ip,
            models.Alert.timestamp >= run.started_at,
        ).order_by(models.Alert.timestamp, models.Alert.id).all()
        db.add_all([models.LabRunAlert(run_id=run.id, alert_id=alert.id) for alert in alert_rows])
        db.commit()

        if alert_rows:
            correlate_open_alerts(db, window_minutes=10)
            alert_ids = [alert.id for alert in alert_rows]
            incident_links = db.query(models.IncidentAlert).filter(
                models.IncidentAlert.alert_id.in_(alert_ids)
            ).all()
            incident_ids = sorted({link.incident_id for link in incident_links})
            db.add_all([
                models.LabRunIncident(run_id=run.id, incident_id=incident_id)
                for incident_id in incident_ids
            ])
            db.commit()

        run = db.get(models.LabRun, run.id)
        run.status = "completed"
        run.ended_at = datetime.utcnow()
        db.commit()
        db.refresh(run)
    except Exception as error:
        db.rollback()
        run = db.get(models.LabRun, run.id)
        run.status = "failed"
        run.error = str(error)
        run.ended_at = datetime.utcnow()
        db.commit()
        db.refresh(run)
    return run


def _telemetry_as_dict(event_type, row):
    if event_type == "connection":
        destination_ip, source_port, destination_port = row.dst_ip, row.src_port, row.dst_port
        protocol = row.protocol
        details = {"connection_state": row.connection_state, "duration": row.duration,
                   "bytes_sent": row.bytes_sent, "bytes_received": row.bytes_received}
    elif event_type == "dns":
        destination_ip, source_port, destination_port, protocol = row.dst_dns_server, None, None, "dns"
        details = {"queried_domain": row.queried_domain, "query_type": row.query_type,
                   "response_code": row.response_code}
    elif event_type == "http":
        destination_ip, source_port, destination_port, protocol = row.dst_ip, None, None, "http"
        details = {"method": row.method, "host": row.host, "uri": row.uri,
                   "status_code": row.status_code, "user_agent": row.user_agent}
    else:
        destination_ip, source_port, destination_port, protocol = row.dst_ip, None, None, "tls"
        details = {"server_name": row.server_name, "version": row.version, "cipher": row.cipher}
    return {
        "id": row.id, "event_type": event_type, "timestamp": row.timestamp,
        "source_ip": row.src_ip, "destination_ip": destination_ip,
        "source_port": source_port, "destination_port": destination_port,
        "protocol": protocol, "details": details, "is_simulated": True,
    }


def run_response(db: Session, run: models.LabRun, detail: bool = False):
    alerts = [link.alert for link in run.alert_links]
    incidents = [link.incident for link in run.incident_links]
    response = {
        "id": run.id,
        "scenario": {"id": run.scenario_id, "name": run.scenario_name},
        "start_time": run.started_at,
        "end_time": run.ended_at,
        "status": run.status,
        "generated_event_count": run.generated_event_count,
        "alert_ids": [alert.id for alert in alerts],
        "incident_ids": [incident.id for incident in incidents],
    }
    if run.error:
        response["error"] = run.error
    if detail:
        response["alerts"] = [
            {"id": alert.id, "timestamp": alert.timestamp, "rule_name": alert.rule_name,
             "alert_type": alert.alert_type, "severity": alert.severity, "status": alert.status,
             "src_ip": alert.src_ip, "dst_ip": alert.dst_ip, "description": alert.description,
             "evidence": alert.evidence}
            for alert in alerts
        ]
        response["incidents"] = [
            {"id": incident.id, "title": incident.title, "severity": incident.severity,
             "status": incident.status}
            for incident in incidents
        ]
        by_type = {}
        for link in run.telemetry_links:
            by_type.setdefault(link.event_type, []).append(link.event_id)
        telemetry = []
        for event_type, ids in by_type.items():
            model = EVENT_MODELS.get(event_type)
            if model is None:
                continue
            rows = db.query(model).filter(model.id.in_(ids)).all()
            telemetry.extend(_telemetry_as_dict(event_type, row) for row in rows)
        telemetry.sort(key=lambda event: (event["timestamp"], event["id"]), reverse=True)
        response["generated_telemetry"] = telemetry
    return response
