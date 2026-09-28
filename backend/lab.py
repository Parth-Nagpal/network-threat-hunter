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


def _synthetic_source_ip(run_id: int) -> str:
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
    return rows


def _event_type(event) -> str:
    if isinstance(event, models.ConnectionEvent):
        return "connection"
    if isinstance(event, models.DNSEvent):
        return "dns"
    if isinstance(event, models.HTTPEvent):
        return "http"
    return "tls"


def _run_detection(db: Session, scenario_id: str) -> None:
    if scenario_id == "port-scan":
        detect_port_scan(db, time_window_seconds=60, threshold=10)
    elif scenario_id == "network-sweep":
        detect_network_sweep(db, time_window_seconds=60, threshold=10)
    elif scenario_id == "ssh-brute-force":
        detect_ssh_brute_force(db, time_window_seconds=60, threshold=5)
    elif scenario_id == "beaconing":
        detect_beaconing(db, time_window_seconds=3600, min_connections=5, max_jitter_cov=0.25)


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

    source_ip = _synthetic_source_ip(run.id)
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
        _run_detection(db, scenario_id)
        alert_rows = db.query(models.Alert).filter(
            models.Alert.src_ip == source_ip,
            models.Alert.rule_name == scenario["detection"],
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
