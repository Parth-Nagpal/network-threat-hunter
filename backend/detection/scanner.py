import json
from datetime import datetime, timedelta
from typing import List, Dict, Set
from sqlalchemy.orm import Session
from sqlalchemy import func
import models
import schemas

def detect_port_scan(db: Session, time_window_seconds: int = 60, threshold: int = 10) -> int:
    """
    Detects port scans from connection events in the database.
    Returns the number of new alerts generated.
    """
    connections = db.query(
        models.ConnectionEvent.src_ip,
        models.ConnectionEvent.dst_ip,
        models.ConnectionEvent.dst_port,
        models.ConnectionEvent.timestamp
    ).order_by(models.ConnectionEvent.timestamp).all()
    
    # Group by src_ip, dst_ip
    grouped = {}
    for c in connections:
        key = (c.src_ip, c.dst_ip)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append((c.timestamp, c.dst_port))
    
    alerts_created = 0
    
    for (src_ip, dst_ip), events in grouped.items():
        window_start = 0
        
        for i in range(len(events)):
            current_time, current_port = events[i]
            
            # Move window_start to keep it within the time window
            while (current_time - events[window_start][0]).total_seconds() > time_window_seconds:
                window_start += 1
            
            # Rebuild seen ports for current window
            seen_ports = set(e[1] for e in events[window_start:i+1])
            
            if len(seen_ports) >= threshold:
                existing_alert = db.query(models.Alert).filter(
                    models.Alert.rule_name == "Port Scan Detected",
                    models.Alert.src_ip == src_ip,
                    models.Alert.dst_ip == dst_ip,
                    models.Alert.timestamp >= current_time - timedelta(seconds=time_window_seconds)
                ).first()
                
                if not existing_alert:
                    evidence = {
                        "port_count": len(seen_ports),
                        "ports_observed": list(seen_ports),
                        "time_window": time_window_seconds
                    }
                    alert_schema = schemas.AlertCreate(
                        timestamp=current_time,
                        rule_name="Port Scan Detected",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        description=f"Source {src_ip} scanned {len(seen_ports)} distinct ports on {dst_ip} within {time_window_seconds} seconds.",
                        evidence=json.dumps(evidence)
                    )
                    db_alert = models.Alert(**alert_schema.model_dump())
                    db.add(db_alert)
                    db.commit()
                    alerts_created += 1
                    
                # advance window_start to prevent multiple alerts for the same scan burst
                window_start = i + 1
                
    return alerts_created


def detect_network_sweep(db: Session, time_window_seconds: int = 60, threshold: int = 10) -> int:
    """
    Detects network sweeps (horizontal scans) from connection events in the database.
    A sweep is when one source IP contacts many distinct destination IPs on the same port.
    Returns the number of new alerts generated.
    """
    connections = db.query(
        models.ConnectionEvent.src_ip,
        models.ConnectionEvent.dst_ip,
        models.ConnectionEvent.dst_port,
        models.ConnectionEvent.timestamp
    ).order_by(models.ConnectionEvent.timestamp).all()

    # Group by (src_ip, dst_port)
    grouped = {}
    for c in connections:
        key = (c.src_ip, c.dst_port)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append((c.timestamp, c.dst_ip))

    alerts_created = 0

    for (src_ip, dst_port), events in grouped.items():
        window_start = 0

        for i in range(len(events)):
            current_time, current_dst_ip = events[i]

            # Slide window to keep events within the time window
            while (current_time - events[window_start][0]).total_seconds() > time_window_seconds:
                window_start += 1

            # Count distinct destination IPs in the current window
            seen_ips = set(e[1] for e in events[window_start:i + 1])

            if len(seen_ips) >= threshold:
                existing_alert = db.query(models.Alert).filter(
                    models.Alert.rule_name == "Network Sweep Detected",
                    models.Alert.src_ip == src_ip,
                    models.Alert.dst_ip == f"port:{dst_port}",
                    models.Alert.timestamp >= current_time - timedelta(seconds=time_window_seconds)
                ).first()

                if not existing_alert:
                    evidence = {
                        "destination_port": dst_port,
                        "ip_count": len(seen_ips),
                        "ips_observed": list(seen_ips),
                        "time_window": time_window_seconds
                    }
                    alert_schema = schemas.AlertCreate(
                        timestamp=current_time,
                        rule_name="Network Sweep Detected",
                        src_ip=src_ip,
                        dst_ip=f"port:{dst_port}",
                        description=(
                            f"Source {src_ip} swept {len(seen_ips)} distinct hosts "
                            f"on port {dst_port} within {time_window_seconds} seconds."
                        ),
                        evidence=json.dumps(evidence)
                    )
                    db_alert = models.Alert(**alert_schema.model_dump())
                    db.add(db_alert)
                    db.commit()
                    alerts_created += 1

                # Advance past this burst to prevent duplicate alerts
                window_start = i + 1

    return alerts_created


# Zeek connection states that indicate a failed/rejected connection
_SSH_FAIL_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR", "OTH"}
# Zeek connection states that indicate a successfully established session
_SSH_SUCCESS_STATES = {"SF", "S1", "S2", "S3"}


def detect_ssh_brute_force(
    db: Session,
    time_window_seconds: int = 60,
    threshold: int = 5,
) -> int:
    """
    Detects SSH brute-force attempts from connection events in the database.

    A brute-force is flagged when the same source IP makes more than `threshold`
    failed SSH connections (dst_port == 22) to the same destination IP within
    `time_window_seconds`.  If a successful SSH connection follows the failures
    it is included in the evidence.

    Returns the number of new alerts generated.
    """
    # Fetch only SSH traffic (port 22), ordered by time
    ssh_conns = (
        db.query(
            models.ConnectionEvent.src_ip,
            models.ConnectionEvent.dst_ip,
            models.ConnectionEvent.connection_state,
            models.ConnectionEvent.timestamp,
        )
        .filter(models.ConnectionEvent.dst_port == 22)
        .order_by(models.ConnectionEvent.timestamp)
        .all()
    )

    # Group by (src_ip, dst_ip) → list of (timestamp, connection_state)
    grouped: dict = {}
    for c in ssh_conns:
        key = (c.src_ip, c.dst_ip)
        grouped.setdefault(key, []).append((c.timestamp, c.connection_state))

    alerts_created = 0

    for (src_ip, dst_ip), events in grouped.items():
        window_start = 0

        for i in range(len(events)):
            current_time, _ = events[i]

            # Slide the window
            while (current_time - events[window_start][0]).total_seconds() > time_window_seconds:
                window_start += 1

            window_events = events[window_start : i + 1]
            failed = [e for e in window_events if e[1] in _SSH_FAIL_STATES]

            if len(failed) >= threshold:
                # Deduplicate: skip if an alert already covers this window
                existing_alert = db.query(models.Alert).filter(
                    models.Alert.rule_name == "SSH Brute Force Detected",
                    models.Alert.src_ip == src_ip,
                    models.Alert.dst_ip == dst_ip,
                    models.Alert.timestamp >= current_time - timedelta(seconds=time_window_seconds),
                ).first()

                if not existing_alert:
                    # Scan the rest of events within the same window for any success
                    window_end_time = events[window_start][0] + timedelta(seconds=time_window_seconds)
                    success = [
                        e for e in events[i + 1:]
                        if e[0] <= window_end_time and e[1] in _SSH_SUCCESS_STATES
                    ]

                    evidence = {
                        "failed_attempts": len(failed),
                        "time_window": time_window_seconds,
                        "successful_login": bool(success),
                        "success_timestamps": [str(e[0]) for e in success],
                    }
                    desc = (
                        f"Source {src_ip} made {len(failed)} failed SSH attempts "
                        f"to {dst_ip} within {time_window_seconds} seconds."
                    )
                    if success:
                        desc += " A subsequent successful login was observed."

                    alert_schema = schemas.AlertCreate(
                        timestamp=current_time,
                        rule_name="SSH Brute Force Detected",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        description=desc,
                        evidence=json.dumps(evidence),
                    )
                    db_alert = models.Alert(**alert_schema.model_dump())
                    db.add(db_alert)
                    db.commit()
                    alerts_created += 1

                # Advance past this burst to avoid duplicate alerts
                window_start = i + 1

    return alerts_created


def detect_dns_anomaly(
    db: Session,
    time_window_seconds: int = 60,
    query_count_threshold: int = 100,
    max_query_length: int = 50,
) -> int:
    """
    Detects DNS anomalies from DNS events in the database.

    Two signals are combined per source IP within each time window:
      1. High query frequency  – total DNS queries >= query_count_threshold
      2. Long query names      – any queried_domain longer than max_query_length
         (typical of DNS tunnelling or DGA-generated names)

    Both signals are evaluated together; an alert is raised if either fires.
    Evidence includes source IP, query count, max query length, and a sample
    of the suspicious (long) domain names observed.

    Returns the number of new alerts generated.
    """
    dns_events = (
        db.query(
            models.DNSEvent.src_ip,
            models.DNSEvent.queried_domain,
            models.DNSEvent.timestamp,
        )
        .order_by(models.DNSEvent.timestamp)
        .all()
    )

    # Group by src_ip → list of (timestamp, queried_domain)
    grouped: dict = {}
    for d in dns_events:
        grouped.setdefault(d.src_ip, []).append((d.timestamp, d.queried_domain))

    alerts_created = 0

    for src_ip, events in grouped.items():
        window_start = 0

        for i in range(len(events)):
            current_time, _ = events[i]

            # Slide window
            while (current_time - events[window_start][0]).total_seconds() > time_window_seconds:
                window_start += 1

            window_events = events[window_start : i + 1]
            query_count = len(window_events)
            domains = [e[1] for e in window_events]
            long_domains = [d for d in domains if len(d) > max_query_length]
            actual_max_len = max((len(d) for d in domains), default=0)

            high_frequency = query_count >= query_count_threshold
            long_names = bool(long_domains)

            if high_frequency or long_names:
                existing_alert = db.query(models.Alert).filter(
                    models.Alert.rule_name == "DNS Anomaly Detected",
                    models.Alert.src_ip == src_ip,
                    models.Alert.timestamp >= current_time - timedelta(seconds=time_window_seconds),
                ).first()

                if not existing_alert:
                    signals = []
                    if high_frequency:
                        signals.append(f"high query frequency ({query_count} queries)")
                    if long_names:
                        signals.append(f"long domain names (max length {actual_max_len})")

                    evidence = {
                        "query_count": query_count,
                        "max_query_length": actual_max_len,
                        "long_domains_sample": long_domains[:10],
                        "high_frequency": high_frequency,
                        "time_window": time_window_seconds,
                    }
                    desc = (
                        f"Source {src_ip} triggered DNS anomaly: "
                        + " and ".join(signals)
                        + f" within {time_window_seconds} seconds."
                    )
                    alert_schema = schemas.AlertCreate(
                        timestamp=current_time,
                        rule_name="DNS Anomaly Detected",
                        src_ip=src_ip,
                        dst_ip="dns",
                        description=desc,
                        evidence=json.dumps(evidence),
                    )
                    db_alert = models.Alert(**alert_schema.model_dump())
                    db.add(db_alert)
                    db.commit()
                    alerts_created += 1

                # Advance past this burst
                window_start = i + 1

    return alerts_created
