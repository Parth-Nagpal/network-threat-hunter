# Network Threat Hunter

A local network threat hunting and investigation platform designed to ingest network telemetry, detect suspicious behavior, correlate alerts into incidents, and provide an analyst investigation interface.

## Project Purpose
This project is an educational/foundation platform for network threat hunting. It aims to demonstrate how network data can be ingested, analyzed for threats, and presented to security analysts in a clean, professional dashboard. 

## Current Architecture (Phase 1)
- **Frontend**: React + Vite + TypeScript (Dashboard Shell)
- **Backend**: Python + FastAPI
- **Database**: PostgreSQL
- **Orchestration**: Docker & Docker Compose

All components are designed to run locally without cloud dependencies.

## Technology Stack
- Python 3.12+ (FastAPI, SQLAlchemy)
- Node.js 20+ (React, Vite)
- PostgreSQL 15+
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

## How to Stop the Project
To stop the running services, execute:
```bash
docker-compose down
```
*(Add `-v` to remove database volumes and reset data).*

## Current Implementation Status
**Phase 1 Complete:**
- Basic project structure established.
- FastAPI backend with health endpoints configured.
- React frontend with dark-mode dashboard shell and backend connectivity.
- PostgreSQL database provisioned via Docker Compose.

## Planned Future Modules
- **Ingestion**: Ingesting logs/telemetry from network devices.
- **Detection**: Suricata/Zeek integration for signature-based detection.
- **Correlation**: Grouping alerts into incidents based on logic rules.
- **Hunting**: Interface to query historical network logs and behavior.
- **Authentication**: User management and RBAC.
