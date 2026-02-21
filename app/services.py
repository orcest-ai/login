import os
import json
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from passlib.context import CryptContext
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from user_agents import parse as parse_user_agent

from .models import User, Session as UserSession, AccessGrant, OIDCClient, AuditLog, AuthorizationCode, RefreshToken, UsageMetric

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = os.environ.get("SSO_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "RS256"  # Use RSA for proper JWKS
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 1
MAX_ACCESS_GRANT_DAYS = 30

# Generate RSA key pair for JWT signing
def generate_rsa_keypair():
    """Generate RSA key pair for JWT signing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

# Load or generate RSA keys
RSA_PRIVATE_KEY = os.environ.get("RSA_PRIVATE_KEY")
RSA_PUBLIC_KEY = os.environ.get("RSA_PUBLIC_KEY")

if not RSA_PRIVATE_KEY or not RSA_PUBLIC_KEY:
    logger.warning("RSA keys not found in environment, generating new ones")
    RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa_keypair()

# Service roles and permissions
ROLES = {
    "admin": {
        "services": ["*"], 
        "description": "Full access to all services + admin panel"
    },
    "developer": {
        "services": ["rm.orcest.ai", "llm.orcest.ai", "agent.orcest.ai", "ide.orcest.ai"], 
        "description": "Access to development tools"
    },
    "researcher": {
        "services": ["rm.orcest.ai", "llm.orcest.ai", "orcest.ai"], 
        "description": "Access to LLM and research services"
    },
    "viewer": {
        "services": ["llm.orcest.ai"], 
        "description": "Read-only access to chat"
    },
}



MODEL_PRICING = {
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
    "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
}

SERVICE_DOMAINS = {
    "lamino": "llm.orcest.ai",
    "maestrist": "agent.orcest.ai", 
    "orcide": "ide.orcest.ai",
    "orcest": "orcest.ai",
    "rainymodel": "rm.orcest.ai"
}


class UserService:
    """Service for user management operations"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_user(db: Session, email: str, name: str, password: str, role: str = "viewer", created_by: str = "system") -> User:
        """Create a new user"""
        if role not in ROLES:
            raise ValueError(f"Invalid role: {role}")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            raise ValueError(f"User with email {email} already exists")
        
        user = User(
            email=email,
            name=name,
            password_hash=UserService.hash_password(password),
            role=role,
            is_active=True
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Log user creation
        AuditService.log_action(
            db, user.id, "user_created", 
            details={"created_by": created_by, "role": role}
        )
        
        logger.info(f"User created: {email} with role {role}")
        return user
    
    @staticmethod
    def authenticate_user(db: Session, email: str, password: str, ip_address: str = None, user_agent: str = None) -> Optional[User]:
        """Authenticate a user with email and password"""
        user = db.query(User).filter(User.email == email).first()
        
        if not user or not user.is_active:
            AuditService.log_action(
                db, None, "login_failed", ip_address, user_agent,
                details={"email": email, "reason": "user_not_found_or_inactive"}
            )
            return None
        
        if not UserService.verify_password(password, user.password_hash):
            AuditService.log_action(
                db, user.id, "login_failed", ip_address, user_agent,
                details={"reason": "invalid_password"}
            )
            return None
        
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        
        AuditService.log_action(
            db, user.id, "login_success", ip_address, user_agent
        )
        
        return user
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email"""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def list_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
        """List all users with pagination"""
        return db.query(User).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_user(db: Session, user_id: str, **kwargs) -> Optional[User]:
        """Update user fields"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        
        for key, value in kwargs.items():
            if hasattr(user, key):
                if key == "password" and value:
                    setattr(user, "password_hash", UserService.hash_password(value))
                else:
                    setattr(user, key, value)
        
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def set_active_status(db: Session, user_id: str, is_active: bool, changed_by: str) -> Optional[User]:
        """Activate/deactivate a user"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None

        user.is_active = is_active
        db.commit()
        db.refresh(user)

        AuditService.log_action(
            db, user.id, "user_status_changed",
            details={"is_active": is_active, "changed_by": changed_by}
        )

        return user

    @staticmethod
    def reset_password(db: Session, user_id: str, new_password: str, changed_by: str) -> Optional[User]:
        """Reset password for a user"""
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None

        user.password_hash = UserService.hash_password(new_password)
        db.commit()
        db.refresh(user)

        AuditService.log_action(
            db, user.id, "password_reset",
            details={"changed_by": changed_by}
        )

        return user


class SessionService:
    """Service for session management"""
    
    @staticmethod
    def create_session(db: Session, user: User, ip_address: str = None, user_agent: str = None) -> UserSession:
        """Create a new user session"""
        # Parse user agent for device info
        device_info = "Unknown"
        if user_agent:
            ua = parse_user_agent(user_agent)
            device_info = f"{ua.browser.family} on {ua.os.family}"
        
        # TODO: Add GeoIP lookup for location
        location = "Unknown"
        
        session = UserSession(
            user_id=user.id,
            token=secrets.token_urlsafe(64),
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            location=location,
            expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        db.add(session)
        db.commit()
        db.refresh(session)
        
        return session
    
    @staticmethod
    def get_session(db: Session, token: str) -> Optional[UserSession]:
        """Get session by token"""
        return db.query(UserSession).filter(
            and_(
                UserSession.token == token,
                UserSession.revoked == False,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        ).first()
    
    @staticmethod
    def revoke_session(db: Session, token: str) -> bool:
        """Revoke a session"""
        session = db.query(UserSession).filter(UserSession.token == token).first()
        if session:
            session.revoked = True
            db.commit()
            return True
        return False
    
    @staticmethod
    def revoke_user_sessions(db: Session, user_id: str, except_token: str = None) -> int:
        """Revoke all sessions for a user except the specified one"""
        query = db.query(UserSession).filter(
            and_(
                UserSession.user_id == user_id,
                UserSession.revoked == False
            )
        )
        
        if except_token:
            query = query.filter(UserSession.token != except_token)
        
        count = query.count()
        query.update({"revoked": True})
        db.commit()
        
        return count
    
    @staticmethod
    def cleanup_expired_sessions(db: Session) -> int:
        """Clean up expired sessions"""
        count = db.query(UserSession).filter(
            UserSession.expires_at < datetime.now(timezone.utc)
        ).count()
        
        db.query(UserSession).filter(
            UserSession.expires_at < datetime.now(timezone.utc)
        ).delete()
        
        db.commit()
        return count


class AccessGrantService:
    """Service for managing access grants"""
    
    @staticmethod
    def grant_access(db: Session, user_id: str, service_name: str, granted_by: str, days: int = 30) -> AccessGrant:
        """Grant access to a service for a user"""
        if days > MAX_ACCESS_GRANT_DAYS:
            raise ValueError(f"Access grant cannot exceed {MAX_ACCESS_GRANT_DAYS} days")
        
        # Revoke existing grants for the same service
        db.query(AccessGrant).filter(
            and_(
                AccessGrant.user_id == user_id,
                AccessGrant.service_name == service_name
            )
        ).delete()
        
        grant = AccessGrant(
            user_id=user_id,
            service_name=service_name,
            granted_by=granted_by,
            expires_at=datetime.now(timezone.utc) + timedelta(days=days)
        )
        
        db.add(grant)
        db.commit()
        db.refresh(grant)
        
        AuditService.log_action(
            db, user_id, "access_granted",
            details={"service": service_name, "granted_by": granted_by, "days": days}
        )
        
        return grant
    
    @staticmethod
    def check_access(db: Session, user: User, service_name: str) -> bool:
        """Check if user has access to a service"""
        # Admin has access to everything
        if user.role == "admin":
            return True
        
        # Check role-based access
        role_services = ROLES.get(user.role, {}).get("services", [])
        if "*" in role_services or service_name in role_services:
            # Check for active access grant
            grant = db.query(AccessGrant).filter(
                and_(
                    AccessGrant.user_id == user.id,
                    AccessGrant.service_name == service_name,
                    AccessGrant.expires_at > datetime.now(timezone.utc)
                )
            ).first()
            
            return grant is not None
        
        return False
    
    @staticmethod
    def list_user_grants(db: Session, user_id: str) -> List[AccessGrant]:
        """List all access grants for a user"""
        return db.query(AccessGrant).filter(AccessGrant.user_id == user_id).all()
    
    @staticmethod
    def revoke_access(db: Session, user_id: str, service_name: str) -> bool:
        """Revoke access to a service"""
        count = db.query(AccessGrant).filter(
            and_(
                AccessGrant.user_id == user_id,
                AccessGrant.service_name == service_name
            )
        ).delete()
        
        db.commit()
        
        if count > 0:
            AuditService.log_action(
                db, user_id, "access_revoked",
                details={"service": service_name}
            )
        
        return count > 0


class AuditService:
    """Service for audit logging"""
    
    @staticmethod
    def log_action(db: Session, user_id: str = None, action: str = "", ip_address: str = None, 
                   user_agent: str = None, details: Dict[str, Any] = None):
        """Log an audit event"""
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps(details) if details else None
        )
        
        db.add(log_entry)
        db.commit()


class AnalyticsService:
    """Service for usage and RainyModel analytics"""

    @staticmethod
    def estimate_cost(model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        pricing = MODEL_PRICING.get(model_name, MODEL_PRICING["gpt-4o-mini"])
        input_cost = (prompt_tokens / 1_000_000) * pricing["input"]
        output_cost = (completion_tokens / 1_000_000) * pricing["output"]
        return round(input_cost + output_cost, 6)

    @staticmethod
    def create_usage_metric(db: Session, user_id: str, subsystem: str, model_name: str = None,
                            prompt_tokens: int = 0, completion_tokens: int = 0,
                            quality_score: int = None, latency_ms: int = None, meta: Dict[str, Any] = None) -> UsageMetric:
        total_tokens = (prompt_tokens or 0) + (completion_tokens or 0)
        estimated_cost = AnalyticsService.estimate_cost(model_name or "gpt-4o-mini", prompt_tokens or 0, completion_tokens or 0)

        metric = UsageMetric(
            user_id=user_id,
            subsystem=subsystem,
            model_name=model_name,
            prompt_tokens=prompt_tokens or 0,
            completion_tokens=completion_tokens or 0,
            total_tokens=total_tokens,
            estimated_cost=str(estimated_cost),
            quality_score=quality_score,
            latency_ms=latency_ms,
            meta=json.dumps(meta) if meta else None
        )
        db.add(metric)
        db.commit()
        db.refresh(metric)
        return metric

    @staticmethod
    def get_admin_dashboard_stats(db: Session) -> Dict[str, Any]:
        subsystems = db.query(UsageMetric.subsystem, func.count(UsageMetric.id)).group_by(UsageMetric.subsystem).all()
        models = db.query(UsageMetric.model_name, func.sum(UsageMetric.total_tokens)).group_by(UsageMetric.model_name).all()
        quality_avg = db.query(func.avg(UsageMetric.quality_score)).scalar() or 0
        total_cost = sum(float(row.estimated_cost or 0) for row in db.query(UsageMetric).all())

        return {
            "subsystem_usage": [{"label": s, "value": c} for s, c in subsystems if s],
            "model_tokens": [{"label": m or "unknown", "value": int(t or 0)} for m, t in models],
            "quality_avg": round(float(quality_avg), 2),
            "total_cost": round(total_cost, 4),
        }

    @staticmethod
    def get_user_activity_details(db: Session, user_id: str) -> Dict[str, Any]:
        metrics = db.query(UsageMetric).filter(UsageMetric.user_id == user_id).order_by(UsageMetric.created_at.desc()).limit(100).all()

        total_tokens = sum(m.total_tokens for m in metrics)
        total_cost = sum(float(m.estimated_cost or 0) for m in metrics)
        avg_quality = round(sum((m.quality_score or 0) for m in metrics) / len(metrics), 2) if metrics else 0

        return {
            "total_tokens": total_tokens,
            "total_cost": round(total_cost, 4),
            "avg_quality": avg_quality,
            "records": metrics,
        }


class JWTService:
    """Service for JWT token management"""
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_hex(16),
            "iss": os.environ.get("SSO_BASE_URL", "https://login.orcest.ai")
        })
        return jwt.encode(to_encode, RSA_PRIVATE_KEY, algorithm=ALGORITHM)
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, RSA_PUBLIC_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None
    
    @staticmethod
    def get_jwks() -> dict:
        """Get JWKS (JSON Web Key Set) for token verification"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        import base64
        
        public_key = load_pem_public_key(RSA_PUBLIC_KEY.encode())
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format
        def int_to_base64url(val):
            byte_length = (val.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(val.to_bytes(byte_length, 'big')).decode().rstrip('=')
        
        return {
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "orcest-sso-key-1",
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e)
            }]
        }


class OIDCService:
    """Service for OIDC operations"""
    
    @staticmethod
    def init_default_clients(db: Session):
        """Initialize default OIDC clients"""
        default_clients = [
            {
                "client_id": "rainymodel",
                "service_name": "RainyModel",
                "redirect_uris": ["https://rm.orcest.ai/auth/callback"]
            },
            {
                "client_id": "lamino",
                "service_name": "Lamino",
                "redirect_uris": [
                    "https://llm.orcest.ai/auth/callback",
                    "https://orcest.ai/lamino/auth/callback"
                ]
            },
            {
                "client_id": "maestrist",
                "service_name": "Maestrist", 
                "redirect_uris": ["https://agent.orcest.ai/auth/callback"]
            },
            {
                "client_id": "orcide",
                "service_name": "Orcide",
                "redirect_uris": ["https://ide.orcest.ai/auth/callback"]
            },
            {
                "client_id": "orcest",
                "service_name": "Orcest AI",
                "redirect_uris": ["https://orcest.ai/auth/callback"]
            }
        ]
        
        for client_data in default_clients:
            existing = db.query(OIDCClient).filter(OIDCClient.client_id == client_data["client_id"]).first()
            if not existing:
                client = OIDCClient(
                    client_id=client_data["client_id"],
                    client_secret=os.environ.get(f"OIDC_{client_data['client_id'].upper()}_SECRET", secrets.token_hex(32)),
                    service_name=client_data["service_name"],
                    redirect_uris=json.dumps(client_data["redirect_uris"])
                )
                db.add(client)
        
        db.commit()
    
    @staticmethod
    def get_client(db: Session, client_id: str) -> Optional[OIDCClient]:
        """Get OIDC client by client_id"""
        return db.query(OIDCClient).filter(
            and_(OIDCClient.client_id == client_id, OIDCClient.is_active == True)
        ).first()
    
    @staticmethod
    def create_authorization_code(db: Session, client_id: str, user_email: str, redirect_uri: str, scope: str) -> str:
        """Create an authorization code"""
        code = secrets.token_urlsafe(32)
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_email=user_email,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)  # 5 minute expiry
        )
        
        db.add(auth_code)
        db.commit()
        
        return code
    
    @staticmethod
    def consume_authorization_code(db: Session, code: str) -> Optional[AuthorizationCode]:
        """Consume an authorization code (use once)"""
        auth_code = db.query(AuthorizationCode).filter(
            and_(
                AuthorizationCode.code == code,
                AuthorizationCode.used == False,
                AuthorizationCode.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if auth_code:
            auth_code.used = True
            db.commit()
            
        return auth_code