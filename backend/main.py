from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from database import check_db_connection

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
