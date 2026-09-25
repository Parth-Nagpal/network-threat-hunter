from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class ConnectionEvent(Base):
    __tablename__ = "connection_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_ip = Column(String, index=True)
    dst_port = Column(Integer)
    protocol = Column(String)
    connection_state = Column(String)
    duration = Column(Float, nullable=True)
    bytes_sent = Column(Integer, nullable=True)
    bytes_received = Column(Integer, nullable=True)

class DNSEvent(Base):
    __tablename__ = "dns_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    dst_dns_server = Column(String)
    queried_domain = Column(String, index=True)
    query_type = Column(String)
    response_code = Column(String, nullable=True)

class HTTPEvent(Base):
    __tablename__ = "http_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    method = Column(String)
    host = Column(String, index=True)
    uri = Column(String)
    status_code = Column(Integer, nullable=True)
    user_agent = Column(String, nullable=True)

class SSLEvent(Base):
    __tablename__ = "ssl_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    server_name = Column(String, index=True, nullable=True)
    version = Column(String, nullable=True)
    cipher = Column(String, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    rule_name = Column(String, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    description = Column(String)
    evidence = Column(String)
    # Workflow metadata is populated by the ORM for existing detection paths.
    status = Column(String, nullable=False, default="open", index=True)
    severity = Column(String, nullable=False, default="medium", index=True)
    alert_type = Column(String, nullable=False, default="unknown", index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    def __init__(self, **kwargs):
        rule_name = kwargs.get("rule_name", "")
        kwargs.setdefault("alert_type", rule_name.removesuffix(" Detected") or "unknown")
        severity_by_type = {
            "SSH Brute Force Detected": "high",
            "Port Scan Detected": "medium",
            "Network Sweep Detected": "medium",
            "DNS Anomaly Detected": "medium",
            "Beaconing Detected": "high",
        }
        kwargs.setdefault("severity", severity_by_type.get(rule_name, "medium"))
        super().__init__(**kwargs)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    summary = Column(String, nullable=False, default="")
    severity = Column(String, nullable=False, default="medium", index=True)
    status = Column(String, nullable=False, default="open", index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    alert_links = relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("InvestigationAction", back_populates="incident", cascade="all, delete-orphan")


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    incident = relationship("Incident", back_populates="alert_links")
    alert = relationship("Alert")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    incident = relationship("Incident", back_populates="notes")


class InvestigationAction(Base):
    __tablename__ = "investigation_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String, nullable=False, index=True)
    comment = Column(String, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    incident = relationship("Incident", back_populates="actions")
