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
