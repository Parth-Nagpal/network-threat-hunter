from sqlalchemy import Column, Integer, String, Float, DateTime
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

