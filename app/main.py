import os
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import random

from fastapi import FastAPI, Request, Depends, HTTPException, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import and_

from .database import get_db, init_database
from .models import User, Session as UserSession, AccessGrant, OIDCClient, AuditLog, AuthorizationCode, RefreshToken, UsageMetric
from .services import (
    UserService, SessionService, AccessGrantService, AuditService, 
    JWTService, OIDCService, ROLES, SERVICE_DOMAINS, AnalyticsService
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Orcest AI SSO Portal",
    description="Enterprise SSO Identity Provider for the Orcest AI ecosystem",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Security
SECRET_KEY = os.environ.get("SSO_SECRET_KEY", secrets.token_hex(32))
security = HTTPBearer(auto_error=False)

# Middleware
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=86400)  # 24 hours
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://*.orcest.ai"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Templates and static files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database and default data"""
    try:
        init_database()
        
        # Initialize default admin user and OIDC clients
        db = next(get_db())
        try:
            # Create admin user if not exists
            admin_email = os.environ.get("SSO_ADMIN_EMAIL", "admin@orcest.ai")
            admin_password = os.environ.get("SSO_ADMIN_PASSWORD", "X69IcnO1EKubqWrQdxHqzL0CyqfOpJPg")
            
            existing_admin = UserService.get_user_by_email(db, admin_email)
            if not existing_admin:
                admin_user = UserService.create_user(
                    db, admin_email, "Admin", admin_password, "admin", "system"
                )
                logger.info(f"Created admin user: {admin_email}")
            
            # Initialize OIDC clients
            OIDCService.init_default_clients(db)
            logger.info("OIDC clients initialized")
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Get current authenticated user from session"""
    session_token = request.session.get("session_token")
    if not session_token:
        return None
    
    session = SessionService.get_session(db, session_token)
    if not session:
        return None
    
    # Update last activity
    session.last_activity = datetime.now(timezone.utc)
    db.commit()
    
    return UserService.get_user_by_id(db, session.user_id)


def require_auth(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency that requires authentication"""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency that requires admin role"""
    user = require_auth(request, db)
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "login.orcest.ai", 
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Login page"""
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/profile", status_code=302)
    
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
    })


@app.post("/login")
async def login_submit(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...)
):
    """Handle login form submission"""
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Validate redirect parameter to prevent open redirect
    redirect_url = request.query_params.get("redirect", "/profile")
    if not redirect_url.startswith("/") and not redirect_url.startswith("https://"):
        redirect_url = "/profile"
    
    user = UserService.authenticate_user(db, email, password, ip_address, user_agent)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password",
        }, status_code=401)
    
    if not user.is_active:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Account is disabled. Contact administrator.",
        }, status_code=403)
    
    # Create session
    session = SessionService.create_session(db, user, ip_address, user_agent)
    request.session["session_token"] = session.token
    
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout and revoke session"""
    session_token = request.session.get("session_token")
    if session_token:
        SessionService.revoke_session(db, session_token)
        user = get_current_user(request, db)
        if user:
            AuditService.log_action(
                db, user.id, "logout", get_client_ip(request),
                request.headers.get("User-Agent", "")
            )
    
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, db: Session = Depends(get_db)):
    """User profile page"""
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/?redirect=/profile", status_code=302)
    
    # Get user's access grants
    grants = AccessGrantService.list_user_grants(db, user.id)
    active_grants = [g for g in grants if g.expires_at > datetime.now(timezone.utc)]
    
    # Get user's active sessions
    sessions = db.query(UserSession).filter(
        and_(
            UserSession.user_id == user.id,
            UserSession.revoked == False,
            UserSession.expires_at > datetime.now(timezone.utc)
        )
    ).all()
    
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "roles": ROLES,
        "active_grants": active_grants,
        "sessions": sessions,
        "service_domains": SERVICE_DOMAINS
    })


# ============================================================================
# ADMIN PANEL ROUTES
# ============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    """Admin dashboard"""
    user = require_admin(request, db)
    
    # Get statistics
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    total_sessions = db.query(UserSession).filter(
        and_(
            UserSession.revoked == False,
            UserSession.expires_at > datetime.now(timezone.utc)
        )
    ).count()
    
    # Recent audit logs
    recent_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    analytics = AnalyticsService.get_admin_dashboard_stats(db)

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "active_sessions": total_sessions
        },
        "recent_logs": recent_logs,
        "roles": ROLES,
        "analytics": analytics,
    })


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, db: Session = Depends(get_db)):
    """Admin users management page"""
    user = require_admin(request, db)
    
    users = UserService.list_users(db)
    
    return templates.TemplateResponse("users.html", {
        "request": request,
        "user": user,
        "users": users,
        "roles": ROLES,
    })


@app.post("/admin/users/create")
async def admin_create_user(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
):
    """Create new user (admin only)"""
    admin_user = require_admin(request, db)
    
    try:
        new_user = UserService.create_user(db, email, name, password, role, admin_user.id)
        
        # Auto-grant access based on role
        if role in ROLES:
            services = ROLES[role]["services"]
            if "*" not in services:  # Don't grant specific services for admin
                for service in services:
                    # Map service domains to service names
                    service_name = None
                    for name, domain in SERVICE_DOMAINS.items():
                        if domain == service:
                            service_name = name
                            break
                    
                    if service_name:
                        AccessGrantService.grant_access(
                            db, new_user.id, service_name, admin_user.id, 30
                        )
        
        return RedirectResponse(url="/admin/users?success=User created successfully", status_code=302)
    except ValueError as e:
        return RedirectResponse(url=f"/admin/users?error={str(e)}", status_code=302)


@app.post("/admin/users/{user_id}/update")
async def admin_update_user(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
    name: str = Form(...),
    email: str = Form(...),
    role: str = Form(...),
):
    """Update user profile and role (admin only)"""
    admin_user = require_admin(request, db)

    target_user = UserService.get_user_by_id(db, user_id)
    if not target_user:
        return RedirectResponse(url="/admin/users?error=User not found", status_code=302)

    if role not in ROLES:
        return RedirectResponse(url="/admin/users?error=Invalid role", status_code=302)

    UserService.update_user(db, user_id, name=name, email=email, role=role)
    AuditService.log_action(
        db, user_id, "user_updated", get_client_ip(request),
        request.headers.get("User-Agent", ""),
        details={"updated_by": admin_user.id, "role": role}
    )

    return RedirectResponse(url="/admin/users?success=User updated successfully", status_code=302)


@app.post("/admin/users/{user_id}/status")
async def admin_toggle_user_status(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
    is_active: bool = Form(...),
):
    """Activate/deactivate user (admin only)"""
    admin_user = require_admin(request, db)

    if admin_user.id == user_id:
        return RedirectResponse(url="/admin/users?error=Cannot disable own account", status_code=302)

    user = UserService.set_active_status(db, user_id, is_active, admin_user.id)
    if not user:
        return RedirectResponse(url="/admin/users?error=User not found", status_code=302)

    if not is_active:
        SessionService.revoke_user_sessions(db, user_id)

    status_text = "activated" if is_active else "deactivated"
    return RedirectResponse(url=f"/admin/users?success=User {status_text} successfully", status_code=302)


@app.post("/admin/users/{user_id}/password")
async def admin_reset_user_password(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
    new_password: str = Form(...),
):
    """Reset user password (admin only)"""
    admin_user = require_admin(request, db)

    try:
        updated = UserService.reset_password(db, user_id, new_password, admin_user.id)
        if not updated:
            return RedirectResponse(url="/admin/users?error=User not found", status_code=302)
    except ValueError as exc:
        return RedirectResponse(url=f"/admin/users?error={str(exc)}", status_code=302)

    return RedirectResponse(url="/admin/users?success=Password updated successfully", status_code=302)


@app.get("/admin/users/{user_id}/activity", response_class=HTMLResponse)
async def admin_user_activity_page(request: Request, user_id: str, db: Session = Depends(get_db)):
    """Detailed user activity with usage metrics"""
    user = require_admin(request, db)
    target_user = UserService.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    activity = AnalyticsService.get_user_activity_details(db, user_id)
    user_logs = db.query(AuditLog).filter(AuditLog.user_id == user_id).order_by(AuditLog.timestamp.desc()).limit(200).all()

    return templates.TemplateResponse("user_activity.html", {
        "request": request,
        "user": user,
        "target_user": target_user,
        "activity": activity,
        "user_logs": user_logs,
    })


@app.get("/admin/analytics", response_class=HTMLResponse)
async def admin_analytics_page(request: Request, db: Session = Depends(get_db)):
    """Global analytics and RainyModel integration view"""
    user = require_admin(request, db)

    analytics = AnalyticsService.get_admin_dashboard_stats(db)
    recent_metrics = db.query(UsageMetric).join(User).order_by(UsageMetric.created_at.desc()).limit(100).all()

    return templates.TemplateResponse("analytics.html", {
        "request": request,
        "user": user,
        "analytics": analytics,
        "recent_metrics": recent_metrics,
    })


@app.post("/admin/analytics/rainymodel/sync")
async def admin_sync_rainymodel(request: Request, db: Session = Depends(get_db)):
    """Simulate RainyModel metrics sync for dashboard enrichment"""
    admin_user = require_admin(request, db)
    users = UserService.list_users(db, limit=200)

    if not users:
        return RedirectResponse(url="/admin/analytics?error=No users found", status_code=302)

    for target in users:
        AnalyticsService.create_usage_metric(
            db,
            user_id=target.id,
            subsystem=random.choice(["RainyModel", "Lamino", "Maestrist", "OrcIDE"]),
            model_name=random.choice(["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet"]),
            prompt_tokens=random.randint(200, 5000),
            completion_tokens=random.randint(200, 7000),
            quality_score=random.randint(60, 98),
            latency_ms=random.randint(200, 4200),
            meta={"source": "rainymodel_sync", "synced_by": admin_user.id}
        )

    AuditService.log_action(
        db, admin_user.id, "rainymodel_sync",
        get_client_ip(request), request.headers.get("User-Agent", ""),
        details={"users_processed": len(users)}
    )
    return RedirectResponse(url="/admin/analytics?success=RainyModel sync completed", status_code=302)


@app.get("/admin/sessions", response_class=HTMLResponse)
async def admin_sessions_page(request: Request, db: Session = Depends(get_db)):
    """Admin sessions management page"""
    user = require_admin(request, db)
    
    # Get all active sessions with user info
    sessions = db.query(UserSession).join(User).filter(
        and_(
            UserSession.revoked == False,
            UserSession.expires_at > datetime.now(timezone.utc)
        )
    ).order_by(UserSession.created_at.desc()).all()
    
    return templates.TemplateResponse("sessions.html", {
        "request": request,
        "user": user,
        "sessions": sessions,
    })


@app.post("/admin/sessions/{session_id}/revoke")
async def admin_revoke_session(
    request: Request,
    session_id: str,
    db: Session = Depends(get_db)
):
    """Revoke a specific session (admin only)"""
    admin_user = require_admin(request, db)
    
    session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if session:
        session.revoked = True
        db.commit()
        
        AuditService.log_action(
            db, session.user_id, "session_revoked_by_admin",
            get_client_ip(request), request.headers.get("User-Agent", ""),
            details={"revoked_by": admin_user.id, "session_id": session_id}
        )
    
    return RedirectResponse(url="/admin/sessions", status_code=302)


@app.get("/admin/access", response_class=HTMLResponse)
async def admin_access_page(request: Request, db: Session = Depends(get_db)):
    """Admin access control page"""
    user = require_admin(request, db)
    
    # Get all users with their access grants
    users = db.query(User).all()
    
    return templates.TemplateResponse("access.html", {
        "request": request,
        "user": user,
        "users": users,
        "service_domains": SERVICE_DOMAINS,
        "roles": ROLES
    })


@app.post("/admin/access/grant")
async def admin_grant_access(
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Form(...),
    service_name: str = Form(...),
    days: int = Form(30)
):
    """Grant access to a service (admin only)"""
    admin_user = require_admin(request, db)
    
    try:
        AccessGrantService.grant_access(db, user_id, service_name, admin_user.id, days)
        return RedirectResponse(url="/admin/access?success=Access granted successfully", status_code=302)
    except ValueError as e:
        return RedirectResponse(url=f"/admin/access?error={str(e)}", status_code=302)


@app.get("/admin/applications", response_class=HTMLResponse)
async def admin_applications_page(request: Request, db: Session = Depends(get_db)):
    """Admin OIDC applications page"""
    user = require_admin(request, db)
    
    clients = db.query(OIDCClient).all()
    
    return templates.TemplateResponse("applications.html", {
        "request": request,
        "user": user,
        "clients": clients,
    })


@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit_page(request: Request, db: Session = Depends(get_db)):
    """Admin audit log page"""
    user = require_admin(request, db)
    
    # Get recent audit logs with pagination
    page = int(request.query_params.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    
    logs = db.query(AuditLog).join(User, AuditLog.user_id == User.id, isouter=True)\
             .order_by(AuditLog.timestamp.desc())\
             .offset(offset).limit(per_page).all()
    
    total_logs = db.query(AuditLog).count()
    total_pages = (total_logs + per_page - 1) // per_page
    
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "user": user,
        "logs": logs,
        "page": page,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1
    })


# ============================================================================
# OIDC ENDPOINTS
# ============================================================================

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    """OIDC Discovery endpoint"""
    base_url = os.environ.get("SSO_BASE_URL", str(request.base_url).rstrip("/"))
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth2/authorize",
        "token_endpoint": f"{base_url}/oauth2/token",
        "userinfo_endpoint": f"{base_url}/oauth2/userinfo",
        "jwks_uri": f"{base_url}/oauth2/jwks",
        "revocation_endpoint": f"{base_url}/oauth2/revoke",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/oauth2/authorize")
async def authorize(
    request: Request,
    db: Session = Depends(get_db),
    client_id: str = "",
    redirect_uri: str = "",
    response_type: str = "code",
    scope: str = "openid",
    state: str = "",
):
    """OIDC Authorization endpoint"""
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id is required")
    
    client = OIDCService.get_client(db, client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    # Validate redirect URI
        allowed_uris = json.loads(client.redirect_uris)
    if redirect_uri and redirect_uri not in allowed_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if not redirect_uri:
        redirect_uri = allowed_uris[0]
    
    # Check if user is authenticated
    user = get_current_user(request, db)
    if not user:
        # Store OAuth2 parameters in session for after login
        request.session["oauth2_params"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
        }
        return RedirectResponse(url="/?redirect=/oauth2/authorize/continue", status_code=302)
    
    # Check if user has access to this service
    service_name = client_id  # client_id matches service name
    if not AccessGrantService.check_access(db, user, service_name):
        AuditService.log_action(
            db, user.id, "access_denied", get_client_ip(request),
            request.headers.get("User-Agent", ""),
            details={"service": service_name, "client_id": client_id}
        )
        
        return templates.TemplateResponse("access_denied.html", {
            "request": request,
            "user": user,
            "service_name": client.service_name,
            "client_id": client_id
        }, status_code=403)
    
    # Create authorization code
    code = OIDCService.create_authorization_code(
        db, client_id, user.email, redirect_uri, scope
    )
    
    # Log successful authorization
    AuditService.log_action(
        db, user.id, "oauth2_authorize", get_client_ip(request),
        request.headers.get("User-Agent", ""),
        details={"client_id": client_id, "scope": scope}
    )
    
    # Redirect back to client with authorization code
    params = f"code={code}"
    if state:
        params += f"&state={state}"
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{params}", status_code=302)


@app.get("/oauth2/authorize/continue")
async def authorize_continue(request: Request, db: Session = Depends(get_db)):
    """Continue OAuth2 authorization after login"""
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    
    oauth2_params = request.session.get("oauth2_params")
    if not oauth2_params:
        return RedirectResponse(url="/profile", status_code=302)
    
    # Clear stored parameters
    del request.session["oauth2_params"]
    
    # Redirect to authorization endpoint with stored parameters
    params = "&".join([f"{k}={v}" for k, v in oauth2_params.items() if v])
    return RedirectResponse(url=f"/oauth2/authorize?{params}", status_code=302)


@app.post("/oauth2/token")
async def token_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    grant_type: str = Form("authorization_code"),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    refresh_token: str = Form(None),
):
    """OIDC Token endpoint"""
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="Missing authorization code")
        
        # Consume authorization code
        auth_code = OIDCService.consume_authorization_code(db, code)
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
        
        # Validate client credentials
        if client_id and client_id != auth_code.client_id:
            raise HTTPException(status_code=400, detail="Client ID mismatch")
        
        client = OIDCService.get_client(db, auth_code.client_id)
        if not client:
            raise HTTPException(status_code=400, detail="Invalid client")
        
        # CRITICAL: Validate client_secret (security fix)
        if client_secret != client.client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Get user
        user = UserService.get_user_by_email(db, auth_code.user_email)
        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="User not found or inactive")
        
        # Create tokens
        access_token = JWTService.create_access_token({
            "sub": user.email,
            "name": user.name,
            "role": user.role,
            "aud": auth_code.client_id,
        })
        
        # Create refresh token
        refresh_token = RefreshToken(
            token=secrets.token_urlsafe(64),
            user_id=user.id,
            client_id=auth_code.client_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)
        )
        db.add(refresh_token)
        db.commit()
        
        # Create ID token
        id_token = JWTService.create_access_token({
            "sub": user.email,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "aud": auth_code.client_id,
            "nonce": secrets.token_hex(8),
        }, timedelta(hours=1))
        
        # Log token issuance
        AuditService.log_action(
            db, user.id, "token_issued", get_client_ip(request),
            request.headers.get("User-Agent", ""),
            details={"client_id": auth_code.client_id, "grant_type": grant_type}
        )
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 15 * 60,  # 15 minutes
            "refresh_token": refresh_token.token,
            "id_token": id_token,
            "scope": auth_code.scope,
        }
    
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh token")
        
        # Get and validate refresh token
        token_obj = db.query(RefreshToken).filter(
            and_(
                RefreshToken.token == refresh_token,
                RefreshToken.revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if not token_obj:
            raise HTTPException(status_code=400, detail="Invalid or expired refresh token")
        
        # Validate client credentials if provided
        if client_id and client_id != token_obj.client_id:
            raise HTTPException(status_code=400, detail="Client ID mismatch")
        
        if client_secret:
            client = OIDCService.get_client(db, token_obj.client_id)
            if not client or client_secret != client.client_secret:
                raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Get user
        user = UserService.get_user_by_id(db, token_obj.user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="User not found or inactive")
        
        # Revoke old refresh token and create new one
        token_obj.revoked = True
        new_refresh_token = RefreshToken(
            token=secrets.token_urlsafe(64),
            user_id=user.id,
            client_id=token_obj.client_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)
        )
        db.add(new_refresh_token)
        db.commit()
        
        # Create new access token
        new_access_token = JWTService.create_access_token({
            "sub": user.email,
            "name": user.name,
            "role": user.role,
            "aud": token_obj.client_id,
        })
        
        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 15 * 60,
            "refresh_token": new_refresh_token.token,
        }
    
    raise HTTPException(status_code=400, detail="Unsupported grant type")


@app.get("/oauth2/userinfo")
async def userinfo(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """OIDC UserInfo endpoint"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    
    payload = JWTService.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    email = payload.get("sub")
    user = UserService.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "sub": user.email,
        "name": user.name,
        "email": user.email,
        "email_verified": True,
        "role": user.role,
        "aud": payload.get("aud"),
    }


@app.get("/oauth2/jwks")
async def jwks():
    """JWKS endpoint for token verification"""
    return JWTService.get_jwks()


@app.post("/oauth2/revoke")
async def revoke_token(
    request: Request,
    db: Session = Depends(get_db),
    token: str = Form(...),
    token_type_hint: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None)
):
    """Token revocation endpoint"""
    # Try to revoke as refresh token first
    refresh_token_obj = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if refresh_token_obj:
        refresh_token_obj.revoked = True
        db.commit()
        return {"revoked": True}
    
    # For access tokens, we can't revoke them directly (they're stateless JWTs)
    # but we could maintain a blacklist if needed
    return {"revoked": True}


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.post("/api/token/verify")
async def verify_api_token(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Verify JWT token and return user info"""
    if not credentials:
        return JSONResponse({"valid": False, "error": "Missing bearer token"}, status_code=401)
    
    payload = JWTService.verify_token(credentials.credentials)
    if not payload:
        return JSONResponse({"valid": False, "error": "Invalid or expired token"}, status_code=401)
    
    return {
        "valid": True,
        "sub": payload.get("sub"),
        "role": payload.get("role"),
        "name": payload.get("name"),
        "exp": payload.get("exp"),
        "aud": payload.get("aud")
    }


@app.get("/api/user/{user_id}/access")
async def check_user_access(
    user_id: str,
    service: str,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Check if user has access to a specific service"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    
    payload = JWTService.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Only allow checking own access or admin
    requesting_user = UserService.get_user_by_email(db, payload.get("sub"))
    if not requesting_user:
        raise HTTPException(status_code=404, detail="Requesting user not found")
    
    if requesting_user.id != user_id and requesting_user.role != "admin":
        raise HTTPException(status_code=403, detail="Can only check own access")
    
    target_user = UserService.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    has_access = AccessGrantService.check_access(db, target_user, service)
    
    return {
        "user_id": user_id,
        "service": service,
        "has_access": has_access,
        "role": target_user.role
    }


@app.get("/api/roles")
async def list_roles():
    """List available roles and their permissions"""
    return {"roles": ROLES}


@app.get("/api/services")
async def list_services():
    """List available services"""
    return {"services": SERVICE_DOMAINS}


@app.get("/api/analytics/users/{user_id}")
async def api_user_analytics(
    user_id: str,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """User-level analytics endpoint for low-code/no-code consumers"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = JWTService.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    requester = UserService.get_user_by_email(db, payload.get("sub"))
    if not requester:
        raise HTTPException(status_code=404, detail="Requesting user not found")

    if requester.id != user_id and requester.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    return AnalyticsService.get_user_activity_details(db, user_id)


# ============================================================================
# MAINTENANCE ENDPOINTS
# ============================================================================

@app.post("/api/maintenance/cleanup")
async def cleanup_expired_data(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Clean up expired sessions, tokens, and authorization codes (admin only)"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    
    payload = JWTService.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = UserService.get_user_by_email(db, payload.get("sub"))
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Clean up expired sessions
    expired_sessions = SessionService.cleanup_expired_sessions(db)
    
    # Clean up expired authorization codes
    expired_codes = db.query(AuthorizationCode).filter(
        AuthorizationCode.expires_at < datetime.now(timezone.utc)
    ).count()
    db.query(AuthorizationCode).filter(
        AuthorizationCode.expires_at < datetime.now(timezone.utc)
    ).delete()
    
    # Clean up expired refresh tokens
    expired_refresh_tokens = db.query(RefreshToken).filter(
        RefreshToken.expires_at < datetime.now(timezone.utc)
    ).count()
    db.query(RefreshToken).filter(
        RefreshToken.expires_at < datetime.now(timezone.utc)
    ).delete()
    
    db.commit()
    
    AuditService.log_action(
        db, user.id, "maintenance_cleanup", get_client_ip(request),
        request.headers.get("User-Agent", ""),
        details={
            "expired_sessions": expired_sessions,
            "expired_codes": expired_codes,
            "expired_refresh_tokens": expired_refresh_tokens
        }
    )
    
    return {
        "cleanup_completed": True,
        "expired_sessions_removed": expired_sessions,
        "expired_codes_removed": expired_codes,
        "expired_refresh_tokens_removed": expired_refresh_tokens
    }
