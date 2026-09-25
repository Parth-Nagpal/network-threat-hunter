# Network Threat Hunter

A local network threat hunting and investigation platform designed to ingest network telemetry, detect suspicious behavior, correlate alerts into incidents, and provide an analyst investigation interface.

## Project Purpose
This project is an educational/foundation platform for network threat hunting. It aims to demonstrate how network data can be ingested, analyzed for threats, and presented to security analysts in a clean, professional dashboard. 

## Current Architecture (Phase 2 - Telemetry Ingestion)
- **Frontend**: React + Vite + TypeScript (Dashboard Shell)
- **Backend**: Python + FastAPI
  - Includes an embedded **Zeek** engine (installed via the SUSE OBS repository) for parsing raw network traffic.
- **Database**: PostgreSQL (SQLAlchemy ORM for normalized tables)
- **Orchestration**: Docker & Docker Compose

All components are designed to run locally without cloud dependencies.

## Technology Stack
- Python 3.12+ (FastAPI, SQLAlchemy, Pydantic)
- Node.js 20+ (React, Vite)
- PostgreSQL 15+
- Zeek Network Security Monitor
- Docker Compose

## How to Start the Project
Ensure you have Docker and Docker Compose installed.

1. Clone the repository and navigate to the root directory.
2. Run the following command:
   ```bash
   docker-compose up -d --build
   ```
3. Access the Frontend at: `http://localhost:5173`
4. Access the Backend API documentation at: `http://localhost:8000/docs`

## Phase 2: Zeek Setup & PCAP Ingestion
The Zeek engine is baked directly into the FastAPI backend container to allow seamless execution.

### Ingesting a PCAP
You can submit a PCAP file to the ingestion engine by making a `POST` request to the `/api/ingest/pcap` endpoint.

**Using curl:**
```bash
curl -X POST -F "file=@datasets/sample.pcap" http://localhost:8000/api/ingest/pcap
```

**Example API Response:**
```json
{
  "status": "success",
  "file": "sample.pcap",
  "events": {
    "connections": 1,
    "dns": 0,
    "http": 0,
    "ssl": 0
  }
}
```

### Inspecting Imported Events
To inspect the normalized events directly in the database:
1. Connect to the PostgreSQL container:
   ```bash
   docker exec -it nth_postgres psql -U postgres -d threat_hunter
   ```
2. Query the normalized tables (`connection_events`, `dns_events`, `http_events`, `ssl_events`):
   ```sql
   SELECT * FROM connection_events;
   ```

## How to Stop the Project
To stop the running services, execute:
```bash
docker-compose down
```
*(Add `-v` to remove database volumes and reset data).*

## Planned Future Modules
- **Detection**: Suricata/Zeek integration for signature-based detection.
- **Correlation**: Grouping alerts into incidents based on logic rules.
- **Hunting**: Interface to query historical network logs and behavior.
- **Authentication**: User management and RBAC.
