from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

class ConnectionEventCreate(BaseModel):
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    connection_state: str
    duration: Optional[float] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

class DNSEventCreate(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_dns_server: str
    queried_domain: str
    query_type: str
    response_code: Optional[str] = None

class HTTPEventCreate(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    status_code: Optional[int] = None
    user_agent: Optional[str] = None

class SSLEventCreate(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    server_name: Optional[str] = None
    version: Optional[str] = None
    cipher: Optional[str] = None

class AlertCreate(BaseModel):
    timestamp: datetime
    rule_name: str
    src_ip: str
    dst_ip: str
    description: str
    evidence: str

class AlertResponse(AlertCreate):
    id: int
    alert_type: str
    severity: str
    status: str
    created_at: datetime
    class Config:
        from_attributes = True

class AlertStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]

    class Config:
        extra = "forbid"
