import os
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Any
import models
import schemas
from sqlalchemy.orm import Session

def run_zeek(pcap_path: str, output_dir: str):
    """
    Runs Zeek on the given PCAP file and outputs logs to output_dir.
    """
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Run Zeek
    cmd = ["zeek", "-r", pcap_path, "LogAscii::use_json=T"]
    
    try:
        subprocess.run(cmd, cwd=output_dir, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Zeek failed: {e.stderr}")

def parse_zeek_json(log_path: str) -> List[Dict[str, Any]]:
    """
    Reads a Zeek JSON log file and returns a list of dictionaries.
    """
    events = []
    if not os.path.exists(log_path):
        return events
        
    with open(log_path, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events

def parse_and_store(output_dir: str, db: Session) -> Dict[str, int]:
    """
    Parses Zeek logs from output_dir and stores them in the database.
    """
    stats = {
        "connections": 0,
        "dns": 0,
        "http": 0,
        "ssl": 0
    }
    
    # 1. Parse conn.log
    conn_logs = parse_zeek_json(os.path.join(output_dir, "conn.log"))
    for log in conn_logs:
        try:
            event = schemas.ConnectionEventCreate(
                timestamp=datetime.fromtimestamp(log.get("ts", 0)),
                src_ip=log.get("id.orig_h", ""),
                src_port=log.get("id.orig_p", 0),
                dst_ip=log.get("id.resp_h", ""),
                dst_port=log.get("id.resp_p", 0),
                protocol=log.get("proto", "unknown"),
                connection_state=log.get("conn_state", "unknown"),
                duration=log.get("duration"),
                bytes_sent=log.get("orig_bytes"),
                bytes_received=log.get("resp_bytes")
            )
            db_event = models.ConnectionEvent(**event.model_dump())
            db.add(db_event)
            stats["connections"] += 1
        except Exception as e:
            print(f"Error parsing connection event: {e}")

    # 2. Parse dns.log
    dns_logs = parse_zeek_json(os.path.join(output_dir, "dns.log"))
    for log in dns_logs:
        try:
            event = schemas.DNSEventCreate(
                timestamp=datetime.fromtimestamp(log.get("ts", 0)),
                src_ip=log.get("id.orig_h", ""),
                dst_dns_server=log.get("id.resp_h", ""),
                queried_domain=log.get("query", ""),
                query_type=log.get("qtype_name", ""),
                response_code=log.get("rcode_name")
            )
            db_event = models.DNSEvent(**event.model_dump())
            db.add(db_event)
            stats["dns"] += 1
        except Exception as e:
            print(f"Error parsing dns event: {e}")

    # 3. Parse http.log
    http_logs = parse_zeek_json(os.path.join(output_dir, "http.log"))
    for log in http_logs:
        try:
            event = schemas.HTTPEventCreate(
                timestamp=datetime.fromtimestamp(log.get("ts", 0)),
                src_ip=log.get("id.orig_h", ""),
                dst_ip=log.get("id.resp_h", ""),
                method=log.get("method", ""),
                host=log.get("host", ""),
                uri=log.get("uri", ""),
                status_code=log.get("status_code"),
                user_agent=log.get("user_agent")
            )
            db_event = models.HTTPEvent(**event.model_dump())
            db.add(db_event)
            stats["http"] += 1
        except Exception as e:
            print(f"Error parsing http event: {e}")

    # 4. Parse ssl.log
    ssl_logs = parse_zeek_json(os.path.join(output_dir, "ssl.log"))
    for log in ssl_logs:
        try:
            event = schemas.SSLEventCreate(
                timestamp=datetime.fromtimestamp(log.get("ts", 0)),
                src_ip=log.get("id.orig_h", ""),
                dst_ip=log.get("id.resp_h", ""),
                server_name=log.get("server_name"),
                version=log.get("version"),
                cipher=log.get("cipher")
            )
            db_event = models.SSLEvent(**event.model_dump())
            db.add(db_event)
            stats["ssl"] += 1
        except Exception as e:
            print(f"Error parsing ssl event: {e}")

    db.commit()
    return stats
