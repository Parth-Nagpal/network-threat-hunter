import os
import shutil
import tempfile
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import check_db_connection, get_db, engine
import models
from ingestion.parser import run_zeek, parse_and_store

# Create database tables
models.Base.metadata.create_all(bind=engine)

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

from detection.scanner import detect_port_scan, detect_network_sweep, detect_ssh_brute_force

@app.post("/api/detect/portscan")
def run_port_scan_detection(time_window: int = 60, threshold: int = 10, db: Session = Depends(get_db)):
    """
    Run port scan detection on the current connection events.
    """
    try:
        alerts_created = detect_port_scan(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/sweep")
def run_network_sweep_detection(time_window: int = 60, threshold: int = 10, db: Session = Depends(get_db)):
    """
    Run network sweep detection on the current connection events.
    """
    try:
        alerts_created = detect_network_sweep(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/sshbruteforce")
def run_ssh_brute_force_detection(time_window: int = 60, threshold: int = 5, db: Session = Depends(get_db)):
    """
    Run SSH brute-force detection on the current connection events.
    """
    try:
        alerts_created = detect_ssh_brute_force(db, time_window, threshold)
        return {"status": "success", "alerts_created": alerts_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
