import os
import shutil
import tempfile
import json
from datetime import datetime
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import inspect, text

from database import check_db_connection, get_db, engine
import models
from ingestion.parser import run_zeek, parse_and_store

# Create database tables
models.Base.metadata.create_all(bind=engine)

# create_all does not alter tables in an existing database. Add the Phase 4
# columns in place so existing alert evidence and detection data are preserved.
with engine.begin() as connection:
    alert_columns = {column["name"] for column in inspect(connection).get_columns("alerts")}
    additions = {
        "status": "VARCHAR DEFAULT 'open' NOT NULL",
        "severity": "VARCHAR DEFAULT 'medium' NOT NULL",
        "alert_type": "VARCHAR DEFAULT 'unknown' NOT NULL",
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL",
    }
    for column_name, column_type in additions.items():
        if column_name not in alert_columns:
            connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}"))
    legacy_alerts = connection.execute(
        text("SELECT id, rule_name FROM alerts WHERE alert_type = 'unknown'")
    ).mappings().all()
    for alert in legacy_alerts:
        alert_type = (alert["rule_name"] or "").removesuffix(" Detected") or "unknown"
        connection.execute(
            text("UPDATE alerts SET alert_type = :alert_type WHERE id = :alert_id"),
            {"alert_type": alert_type, "alert_id": alert["id"]},
        )

app = FastAPI(
    title="Network Threat Hunter API",
    description="Backend API for the Network Threat Hunter platform",
    version="0.1.0"
)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, this should be restricted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    """
    Check the health of the application and its dependencies.
    """
    db_healthy = check_db_connection()
    status = "healthy" if db_healthy else "unhealthy"
    return {
        "status": status,
        "database": "connected" if db_healthy else "disconnected",
        "api": "online"
    }

@app.get("/api/info")
def api_info():
    """
    Get basic information about the API.
    """
    return {
        "name": "Network Threat Hunter",
        "version": "0.1.0",
        "description": "API for network threat hunting and investigation"
    }

@app.post("/api/ingest/pcap")
async def ingest_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Ingest a PCAP file, process it with Zeek, and store normalized events.
    """
    if not file.filename.endswith(".pcap") and not file.filename.endswith(".pcapng"):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    pcap_path = os.path.join(temp_dir, file.filename)
    
    try:
        # Save uploaded file
        with open(pcap_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Run Zeek
        zeek_out_dir = os.path.join(temp_dir, "logs")
        run_zeek(pcap_path, zeek_out_dir)
        
        # Parse and store
        stats = parse_and_store(zeek_out_dir, db)
        
        return {
            "status": "success",
            "file": file.filename,
            "events": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

from detection.scanner import detect_port_scan, detect_network_sweep, detect_ssh_brute_force, detect_dns_anomaly, detect_beaconing
from schemas import AlertResponse, AlertStatusUpdate, IncidentCreate, IncidentUpdate
from correlation import correlate_open_alerts


@app.get("/api/hunt")
def hunt_telemetry(
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = Query(default=None, ge=0, le=65535),
    destination_port: int | None = Query(default=None, ge=0, le=65535),
    protocol: str | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Search normalized telemetry across connection, DNS, HTTP, and TLS events."""
    event_sources = [
        (models.ConnectionEvent, "connection", models.ConnectionEvent.dst_ip, models.ConnectionEvent.protocol),
        (models.DNSEvent, "dns", models.DNSEvent.dst_dns_server, None),
        (models.HTTPEvent, "http", models.HTTPEvent.dst_ip, None),
        (models.SSLEvent, "tls", models.SSLEvent.dst_ip, None),
    ]
    results = []
    for model, event_type, destination_column, protocol_column in event_sources:
        # Non-connection event models do not contain port data, so they cannot
        # match a port-constrained search.
        if (source_port is not None or destination_port is not None) and model is not models.ConnectionEvent:
            continue
        if protocol is not None:
            if protocol_column is None:
                if protocol.lower() != event_type:
                    continue
            else:
                # The protocol predicate remains in SQL for connection records.
                pass

        query = db.query(model)
        if source_ip is not None:
            query = query.filter(model.src_ip == source_ip)
        if destination_ip is not None:
            query = query.filter(destination_column == destination_ip)
        if model is models.ConnectionEvent:
            if source_port is not None:
                query = query.filter(model.src_port == source_port)
            if destination_port is not None:
                query = query.filter(model.dst_port == destination_port)
            if protocol is not None:
                query = query.filter(model.protocol == protocol)
        if timestamp_from is not None:
            query = query.filter(model.timestamp >= timestamp_from)
        if timestamp_to is not None:
            query = query.filter(model.timestamp <= timestamp_to)

        rows = query.order_by(model.timestamp.desc(), model.id.desc()).limit(limit).all()
        for row in rows:
            if model is models.ConnectionEvent:
                source_port_value, destination_port_value = row.src_port, row.dst_port
                event_protocol = row.protocol
                details = {
                    "connection_state": row.connection_state,
                    "duration": row.duration,
                    "bytes_sent": row.bytes_sent,
                    "bytes_received": row.bytes_received,
                }
            elif model is models.DNSEvent:
                source_port_value = destination_port_value = None
                event_protocol = "dns"
                details = {
                    "queried_domain": row.queried_domain,
                    "query_type": row.query_type,
                    "response_code": row.response_code,
                }
            elif model is models.HTTPEvent:
                source_port_value = destination_port_value = None
                event_protocol = "http"
                details = {
                    "method": row.method,
                    "host": row.host,
                    "uri": row.uri,
                    "status_code": row.status_code,
                    "user_agent": row.user_agent,
                }
            else:
                source_port_value = destination_port_value = None
                event_protocol = "tls"
                details = {"server_name": row.server_name, "version": row.version, "cipher": row.cipher}

            results.append({
                "id": row.id,
                "event_type": event_type,
                "timestamp": row.timestamp,
                "source_ip": row.src_ip,
                "destination_ip": getattr(row, "dst_ip", getattr(row, "dst_dns_server", None)),
                "source_port": source_port_value,
                "destination_port": destination_port_value,
                "protocol": event_protocol,
                "details": details,
            })

    results.sort(key=lambda event: (event["timestamp"], event["id"]), reverse=True)
    return results[:limit]


@app.get("/api/hunt/alerts/{alert_id}")
def get_hunt_alert_evidence(alert_id: int, db: Session = Depends(get_db)):
    """Return the evidence recorded on an alert; detections do not store event IDs."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        evidence_metadata = json.loads(alert.evidence) if alert.evidence else None
    except (TypeError, json.JSONDecodeError):
        evidence_metadata = None
    return {
        "alert_id": alert.id,
        "rule_name": alert.rule_name,
        "timestamp": alert.timestamp,
        "source_ip": alert.src_ip,
        "destination_ip": alert.dst_ip,
        "description": alert.description,
        "evidence": alert.evidence,
        "evidence_metadata": evidence_metadata,
    }


@app.get("/api/alerts", response_model=list[AlertResponse])
def list_alerts(
    severity: str | None = Query(default=None),
    type: str | None = Query(default=None, alias="type"),
    status: str | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List alerts, newest first, with optional workflow and detection filters."""
    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if type:
        query = query.filter(models.Alert.alert_type == type)
    if status:
        query = query.filter(models.Alert.status == status)
    return query.order_by(models.Alert.created_at.desc(), models.Alert.id.desc()).offset(skip).limit(limit).all()


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.patch("/api/alerts/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, update: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = update.status
    db.commit()
    db.refresh(alert)
    return alert


def _incident_response(incident: models.Incident, include_timeline: bool = True):
    response = {
        "id": incident.id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }
    if include_timeline:
        alerts = sorted(
            (link.alert for link in incident.alert_links),
            key=lambda alert: (alert.timestamp or datetime.min, alert.id),
        )
        response["alerts"] = [
            {
                "id": alert.id,
                "timestamp": alert.timestamp,
                "type": alert.alert_type,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "source_ip": alert.src_ip,
                "destination_ip": alert.dst_ip,
                "description": alert.description,
                "evidence": alert.evidence,
            }
            for alert in alerts
        ]
        response["timeline"] = [
            {
                "timestamp": alert["timestamp"],
                "type": alert["type"],
                "rule_name": alert["rule_name"],
                "severity": alert["severity"],
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "evidence": alert["evidence"],
            }
            for alert in response["alerts"]
        ]
    return response


@app.get("/api/incidents")
def list_incidents(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    incidents = db.query(models.Incident).order_by(
        models.Incident.created_at.desc(), models.Incident.id.desc()
    ).limit(limit).all()
    return [_incident_response(incident, include_timeline=False) for incident in incidents]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_response(incident)


@app.post("/api/incidents")
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)):
    incident = models.Incident(**payload.model_dump())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return _incident_response(incident)


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in payload.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(incident, field, value)
    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(incident)
    return _incident_response(incident)


@app.post("/api/incidents/{incident_id}/alerts/{alert_id}")
def add_alert_to_incident(incident_id: int, alert_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    link = db.query(models.IncidentAlert).filter_by(incident_id=incident_id, alert_id=alert_id).first()
    if link is None:
        db.add(models.IncidentAlert(incident_id=incident_id, alert_id=alert_id))
        incident.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(incident)
    return _incident_response(incident)


@app.delete("/api/incidents/{incident_id}/alerts/{alert_id}")
def remove_alert_from_incident(incident_id: int, alert_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    link = db.query(models.IncidentAlert).filter_by(incident_id=incident_id, alert_id=alert_id).first()
    if link is None:
        raise HTTPException(status_code=404, detail="Alert is not associated with this incident")
    db.delete(link)
    incident.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "removed", "incident_id": incident_id, "alert_id": alert_id}


@app.post("/api/incidents/correlate")
def run_incident_correlation(
    window_minutes: int = Query(default=10, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    incidents = correlate_open_alerts(db, window_minutes=window_minutes)
    return {
        "incidents_created": len(incidents),
        "incidents": [_incident_response(incident) for incident in incidents],
    }

@app.post("/api/detect/portscan")
def run_port_scan_detection(time_window: int = 60, threshold: int = 10, db: Session = Depends(get_db)):
    """Run port scan detection on the current connection events."""
    try:
        alerts_created = detect_port_scan(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/sweep")
def run_network_sweep_detection(time_window: int = 60, threshold: int = 10, db: Session = Depends(get_db)):
    """Run network sweep detection on the current connection events."""
    try:
        alerts_created = detect_network_sweep(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/sshbruteforce")
def run_ssh_brute_force_detection(time_window: int = 60, threshold: int = 5, db: Session = Depends(get_db)):
    """Run SSH brute-force detection on the current connection events."""
    try:
        alerts_created = detect_ssh_brute_force(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/dnsanomaly")
def run_dns_anomaly_detection(
    time_window: int = 60,
    query_count_threshold: int = 100,
    max_query_length: int = 50,
    db: Session = Depends(get_db),
):
    """Run DNS anomaly detection (high frequency + long query names) on DNS events."""
    try:
        alerts_created = detect_dns_anomaly(db, time_window, query_count_threshold, max_query_length)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/beaconing")
def run_beaconing_detection(
    time_window: int = 3600,
    min_connections: int = 5,
    max_jitter_cov: float = 0.25,
    db: Session = Depends(get_db),
):
    """Run beaconing detection based on interval regularity of repeated connections."""
    try:
        alerts_created = detect_beaconing(db, time_window, min_connections, max_jitter_cov)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
