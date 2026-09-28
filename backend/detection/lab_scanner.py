"""Focused behavior detectors used by the local synthetic Attack Lab."""

import ipaddress
import json
from collections import Counter
import models


def _emit(db, *, timestamp, rule_name, src_ip, dst_ip, description, evidence, severity):
    existing = db.query(models.Alert).filter(
        models.Alert.rule_name == rule_name,
        models.Alert.src_ip == src_ip,
    ).first()
    if existing:
        return 0
    db.add(models.Alert(
        timestamp=timestamp,
        rule_name=rule_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description=description,
        evidence=json.dumps(evidence, sort_keys=True),
        severity=severity,
    ))
    db.flush()
    return 1


def detect_rare_destination(db, source_ip: str) -> int:
    """Flag a one-off destination after the same source has normal repeats."""
    events = db.query(models.ConnectionEvent).filter(
        models.ConnectionEvent.src_ip == source_ip,
    ).order_by(models.ConnectionEvent.timestamp).all()
    if len(events) < 4:
        return 0
    counts = Counter(event.dst_ip for event in events)
    rare = sorted(destination for destination, count in counts.items() if count == 1)
    if not rare:
        return 0
    destination = rare[-1]
    event = next(row for row in reversed(events) if row.dst_ip == destination)
    return _emit(
        db, timestamp=event.timestamp, rule_name="Rare Destination Detected",
        src_ip=source_ip, dst_ip=destination,
        description=f"Source {source_ip} contacted the unusual destination {destination} once after repeated connections to other destinations.",
        evidence={"destination": destination, "destination_count": 1, "source_event_count": len(events)},
        severity="low",
    )


def detect_minor_dns_anomaly(db, source_ip: str) -> int:
    events = db.query(models.DNSEvent).filter(
        models.DNSEvent.src_ip == source_ip,
    ).order_by(models.DNSEvent.timestamp).all()
    suspicious = [event for event in events if (event.response_code or "").upper() in {"NXDOMAIN", "SERVFAIL"}]
    if not suspicious:
        return 0
    event = suspicious[-1]
    return _emit(
        db, timestamp=event.timestamp, rule_name="Minor DNS Traffic Anomaly Detected",
        src_ip=source_ip, dst_ip=event.dst_dns_server,
        description=f"Source {source_ip} received an isolated {event.response_code} DNS response.",
        evidence={"query": event.queried_domain, "response_code": event.response_code, "failed_query_count": len(suspicious)},
        severity="low",
    )


def detect_http_anomaly(db, source_ip: str) -> int:
    events = db.query(models.HTTPEvent).filter(
        models.HTTPEvent.src_ip == source_ip,
    ).order_by(models.HTTPEvent.timestamp).all()
    suspicious = [event for event in events if (event.status_code or 0) >= 500 or (event.method or "").upper() in {"TRACE", "CONNECT"}]
    if not suspicious:
        return 0
    event = suspicious[-1]
    return _emit(
        db, timestamp=event.timestamp, rule_name="HTTP Anomaly Detected",
        src_ip=source_ip, dst_ip=event.dst_ip,
        description=f"Source {source_ip} made an anomalous HTTP request ({event.method}, status {event.status_code}).",
        evidence={"method": event.method, "host": event.host, "uri": event.uri, "status_code": event.status_code, "anomaly_count": len(suspicious)},
        severity="medium",
    )


def detect_service_probing(db, source_ip: str, time_window_seconds: int = 60) -> int:
    events = db.query(models.ConnectionEvent).filter(
        models.ConnectionEvent.src_ip == source_ip,
    ).order_by(models.ConnectionEvent.timestamp).all()
    if not events:
        return 0
    ports = sorted({event.dst_port for event in events if event.dst_port is not None})
    if not 3 <= len(ports) < 10 or (events[-1].timestamp - events[0].timestamp).total_seconds() > time_window_seconds:
        return 0
    event = events[-1]
    return _emit(
        db, timestamp=event.timestamp, rule_name="Service Probing Detected",
        src_ip=source_ip, dst_ip=event.dst_ip,
        description=f"Source {source_ip} probed {len(ports)} distinct services on {event.dst_ip}.",
        evidence={"ports_observed": ports, "port_count": len(ports), "time_window": time_window_seconds},
        severity="high",
    )


def detect_lateral_movement(db, source_ip: str) -> int:
    try:
        source = ipaddress.ip_address(source_ip)
    except ValueError:
        return 0
    if not source.is_private:
        return 0
    events = db.query(models.ConnectionEvent).filter(
        models.ConnectionEvent.src_ip == source_ip,
        models.ConnectionEvent.dst_port.in_([22, 445, 3389]),
    ).order_by(models.ConnectionEvent.timestamp).all()
    internal = []
    for event in events:
        try:
            if ipaddress.ip_address(event.dst_ip).is_private:
                internal.append(event)
        except ValueError:
            continue
    destinations = sorted({event.dst_ip for event in internal})
    if len(destinations) < 3:
        return 0
    event = internal[-1]
    return _emit(
        db, timestamp=event.timestamp, rule_name="Lateral Movement Detected",
        src_ip=source_ip, dst_ip=event.dst_ip,
        description=f"Source {source_ip} attempted remote-access connections to {len(destinations)} internal hosts.",
        evidence={"internal_destinations": destinations, "destination_count": len(destinations), "ports_observed": sorted({row.dst_port for row in internal})},
        severity="high",
    )


def detect_large_outbound_transfer(db, source_ip: str, threshold_bytes: int = 10_000_000) -> int:
    events = db.query(models.ConnectionEvent).filter(
        models.ConnectionEvent.src_ip == source_ip,
        models.ConnectionEvent.bytes_sent >= threshold_bytes,
    ).order_by(models.ConnectionEvent.timestamp).all()
    if not events:
        return 0
    event = events[-1]
    return _emit(
        db, timestamp=event.timestamp, rule_name="Large Outbound Transfer Detected",
        src_ip=source_ip, dst_ip=event.dst_ip,
        description=f"Source {source_ip} sent {event.bytes_sent:,} bytes to {event.dst_ip}, above the {threshold_bytes:,}-byte transfer threshold.",
        evidence={"bytes_sent": event.bytes_sent, "threshold_bytes": threshold_bytes, "bytes_received": event.bytes_received},
        severity="critical",
    )


def detect_multistage_attack_chain(db, source_ip: str, window_seconds: int = 600) -> int:
    stages = (
        ("Port Scan Detected", "port_scan"),
        ("SSH Brute Force Detected", "ssh_brute_force"),
        ("Large Outbound Transfer Detected", "suspicious_communication"),
    )
    evidence = []
    stage_alerts = []
    for rule_name, stage in stages:
        alert = db.query(models.Alert).filter(
            models.Alert.src_ip == source_ip,
            models.Alert.rule_name == rule_name,
        ).order_by(models.Alert.timestamp).first()
        if alert is None:
            return 0
        stage_alerts.append(alert)
        evidence.append({"stage": stage, "alert_id": alert.id, "timestamp": alert.timestamp.isoformat()})
    timestamps = [alert.timestamp for alert in stage_alerts]
    if timestamps != sorted(timestamps):
        return 0
    if (timestamps[-1] - timestamps[0]).total_seconds() > window_seconds:
        return 0
    alert = db.query(models.Alert).filter(
        models.Alert.src_ip == source_ip,
        models.Alert.rule_name == "Multi-Stage Attack Chain Detected",
    ).first()
    if alert:
        return 0
    final_stage = stage_alerts[-1]
    return _emit(
        db, timestamp=final_stage.timestamp, rule_name="Multi-Stage Attack Chain Detected",
        src_ip=source_ip, dst_ip=final_stage.dst_ip,
        description=f"Source {source_ip} showed an ordered scan, SSH brute-force, and large-transfer sequence within {window_seconds} seconds.",
        evidence={"stages": evidence, "window_seconds": window_seconds}, severity="critical",
    )
