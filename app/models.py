from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import uuid

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="viewer")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    access_grants = relationship("AccessGrant", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    usage_metrics = relationship("UsageMetric", back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    device_info = Column(Text, nullable=True)
    location = Column(String, nullable=True)  # Country/City from IP
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    last_activity = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    # Indexes
    __table_args__ = (
        Index('ix_sessions_user_active', 'user_id', 'revoked'),
        Index('ix_sessions_expires', 'expires_at'),
    )


class AccessGrant(Base):
    __tablename__ = "access_grants"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    service_name = Column(String, nullable=False)  # "lamino", "maestrist", etc.
    granted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    granted_by = Column(String, nullable=False)  # admin user ID
    
    # Relationships
    user = relationship("User", back_populates="access_grants")
    
    # Indexes
    __table_args__ = (
        Index('ix_access_grants_user_service', 'user_id', 'service_name'),
        Index('ix_access_grants_expires', 'expires_at'),
    )


class OIDCClient(Base):
    __tablename__ = "oidc_clients"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = Column(String, unique=True, nullable=False, index=True)
    client_secret = Column(String, nullable=False)
    service_name = Column(String, nullable=False)
    redirect_uris = Column(Text, nullable=False)  # JSON array as string
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)  # "login", "logout", "access_denied", etc.
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    details = Column(Text, nullable=True)  # JSON details
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('ix_audit_log_user_timestamp', 'user_id', 'timestamp'),
        Index('ix_audit_log_action', 'action'),
        Index('ix_audit_log_timestamp', 'timestamp'),
    )


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    
    code = Column(String, primary_key=True)
    client_id = Column(String, nullable=False)
    user_email = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    scope = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    
    # Indexes
    __table_args__ = (
        Index('ix_auth_codes_expires', 'expires_at'),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    token = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    
    # Indexes
    __table_args__ = (
        Index('ix_refresh_tokens_user', 'user_id'),
        Index('ix_refresh_tokens_expires', 'expires_at'),
    )


class UsageMetric(Base):
    __tablename__ = "usage_metrics"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    subsystem = Column(String, nullable=False)
    model_name = Column(String, nullable=True)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    estimated_cost = Column(String, default="0")
    quality_score = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    meta = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="usage_metrics")

    __table_args__ = (
        Index('ix_usage_metrics_user_created', 'user_id', 'created_at'),
        Index('ix_usage_metrics_subsystem', 'subsystem'),
    )
