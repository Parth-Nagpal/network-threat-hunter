import os
import shutil
import tempfile
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
from schemas import AlertResponse, AlertStatusUpdate


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
