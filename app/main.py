import os
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, Response, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from jose import jwt, JWTError

app = FastAPI(
    title="Orcest AI Login Portal",
    description="SSO Identity Provider for the Orcest AI ecosystem",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

SECRET_KEY = os.environ.get("SSO_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"

def verify_password(password: str, stored: str) -> bool:
    parts = stored.split('$')
    if len(parts) != 2:
        return False
    salt, stored_hash = parts
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return secrets.compare_digest(h.hex(), stored_hash)

USERS_DB: dict = {}
OIDC_CLIENTS: dict = {}
AUTHORIZATION_CODES: dict = {}
REFRESH_TOKENS: dict = {}

ROLES = {
    "admin": {"services": ["*"], "description": "Full access to all services"},
    "developer": {"services": ["rm.orcest.ai", "llm.orcest.ai", "agent.orcest.ai", "ide.orcest.ai"], "description": "Access to development tools"},
    "researcher": {"services": ["rm.orcest.ai", "llm.orcest.ai"], "description": "Access to LLM and chat services"},
    "viewer": {"services": ["llm.orcest.ai"], "description": "Read-only access to chat"},
}


def init_data():
    admin_email = os.environ.get("SSO_ADMIN_EMAIL", "admin@orcest.ai")
    admin_password = os.environ.get("SSO_ADMIN_PASSWORD", "changeme")

    if admin_email not in USERS_DB:
        USERS_DB[admin_email] = {
            "id": str(uuid.uuid4()),
            "email": admin_email,
            "name": "Admin",
            "password_hash": hash_password(admin_password),
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
        }

    default_clients = {
        "rainymodel": {
            "client_id": "rainymodel",
            "client_secret": os.environ.get("OIDC_RAINYMODEL_SECRET", secrets.token_hex(16)),
            "redirect_uris": ["https://rm.orcest.ai/auth/callback"],
            "name": "RainyModel",
        },
        "lamino": {
            "client_id": "lamino",
            "client_secret": os.environ.get("OIDC_LAMINO_SECRET", secrets.token_hex(16)),
            "redirect_uris": ["https://llm.orcest.ai/auth/callback"],
            "name": "Lamino",
        },
        "maestrist": {
            "client_id": "maestrist",
            "client_secret": os.environ.get("OIDC_MAESTRIST_SECRET", secrets.token_hex(16)),
            "redirect_uris": ["https://agent.orcest.ai/auth/callback"],
            "name": "Maestrist",
        },
        "orcide": {
            "client_id": "orcide",
            "client_secret": os.environ.get("OIDC_ORCIDE_SECRET", secrets.token_hex(16)),
            "redirect_uris": ["https://ide.orcest.ai/auth/callback"],
            "name": "Orcide",
        },
        "orcest": {
            "client_id": "orcest",
            "client_secret": os.environ.get("OIDC_ORCEST_SECRET", secrets.token_hex(16)),
            "redirect_uris": ["https://orcest.ai/auth/callback"],
            "name": "Orcest AI",
        },
    }
    OIDC_CLIENTS.update(default_clients)


init_data()


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    token = secrets.token_urlsafe(64)
    REFRESH_TOKENS[token] = {
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).isoformat(),
    }
    return token


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(request: Request):
    token = request.session.get("access_token")
    if not token:
        return None
    payload = verify_token(token)
    if not payload:
        return None
    email = payload.get("sub")
    return USERS_DB.get(email)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "login.orcest.ai", "version": "1.0.0"}


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/profile", status_code=302)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
    })


@app.post("/login")
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    user = USERS_DB.get(email)
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password",
        }, status_code=401)
    if not user.get("active", True):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Account is disabled",
        }, status_code=403)

    access_token = create_access_token({"sub": email, "role": user["role"], "name": user["name"]})
    refresh_token = create_refresh_token(user["id"])

    request.session["access_token"] = access_token
    request.session["refresh_token"] = refresh_token

    redirect_url = request.query_params.get("redirect", "/profile")
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get("/logout")
async def logout(request: Request):
    refresh_token = request.session.get("refresh_token")
    if refresh_token and refresh_token in REFRESH_TOKENS:
        del REFRESH_TOKENS[refresh_token]
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "roles": ROLES,
    })


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/?redirect=/admin", status_code=302)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "users": USERS_DB,
        "clients": OIDC_CLIENTS,
        "roles": ROLES,
    })


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/?redirect=/users", status_code=302)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return templates.TemplateResponse("users.html", {
        "request": request,
        "user": user,
        "users": USERS_DB,
        "roles": ROLES,
    })


@app.post("/users/create")
async def create_user(
    request: Request,
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if email in USERS_DB:
        raise HTTPException(status_code=400, detail="User already exists")
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    USERS_DB[email] = {
        "id": str(uuid.uuid4()),
        "email": email,
        "name": name,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    return RedirectResponse(url="/users", status_code=302)


@app.get("/applications", response_class=HTMLResponse)
async def applications_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/?redirect=/applications", status_code=302)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return templates.TemplateResponse("applications.html", {
        "request": request,
        "user": user,
        "clients": OIDC_CLIENTS,
    })


# --- OIDC Endpoints ---

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    base_url = str(request.base_url).rstrip("/")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth2/authorize",
        "token_endpoint": f"{base_url}/oauth2/token",
        "userinfo_endpoint": f"{base_url}/oauth2/userinfo",
        "jwks_uri": f"{base_url}/oauth2/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


@app.get("/oauth2/authorize")
async def authorize(
    request: Request,
    client_id: str = "",
    redirect_uri: str = "",
    response_type: str = "code",
    scope: str = "openid",
    state: str = "",
):
    if client_id not in OIDC_CLIENTS:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    client = OIDC_CLIENTS[client_id]
    if redirect_uri and redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if not redirect_uri:
        redirect_uri = client["redirect_uris"][0]

    user = get_current_user(request)
    if not user:
        request.session["oauth2_params"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
        }
        return RedirectResponse(url="/?redirect=/oauth2/authorize/continue", status_code=302)

    code = secrets.token_urlsafe(32)
    AUTHORIZATION_CODES[code] = {
        "client_id": client_id,
        "user_email": user["email"],
        "redirect_uri": redirect_uri,
        "scope": scope,
        "created_at": time.time(),
    }

    params = f"code={code}"
    if state:
        params += f"&state={state}"
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{params}", status_code=302)


@app.get("/oauth2/authorize/continue")
async def authorize_continue(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=302)

    oauth2_params = request.session.get("oauth2_params")
    if not oauth2_params:
        return RedirectResponse(url="/profile", status_code=302)

    del request.session["oauth2_params"]

    code = secrets.token_urlsafe(32)
    AUTHORIZATION_CODES[code] = {
        "client_id": oauth2_params["client_id"],
        "user_email": user["email"],
        "redirect_uri": oauth2_params["redirect_uri"],
        "scope": oauth2_params["scope"],
        "created_at": time.time(),
    }

    redirect_uri = oauth2_params["redirect_uri"]
    params = f"code={code}"
    if oauth2_params.get("state"):
        params += f"&state={oauth2_params['state']}"
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{params}", status_code=302)


@app.post("/oauth2/token")
async def token_endpoint(
    request: Request,
    grant_type: str = Form("authorization_code"),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    refresh_token: str = Form(None),
):
    if grant_type == "authorization_code":
        if not code or code not in AUTHORIZATION_CODES:
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        auth_code = AUTHORIZATION_CODES.pop(code)
        if time.time() - auth_code["created_at"] > 300:
            raise HTTPException(status_code=400, detail="Authorization code expired")

        if client_id and client_id != auth_code["client_id"]:
            raise HTTPException(status_code=400, detail="Client ID mismatch")

        user = USERS_DB.get(auth_code["user_email"])
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        access_token = create_access_token({
            "sub": user["email"],
            "name": user["name"],
            "role": user["role"],
            "aud": auth_code["client_id"],
        })
        new_refresh_token = create_refresh_token(user["id"])

        id_token = create_access_token({
            "sub": user["email"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "aud": auth_code["client_id"],
            "nonce": secrets.token_hex(8),
        }, timedelta(hours=1))

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": new_refresh_token,
            "id_token": id_token,
            "scope": auth_code["scope"],
        }

    elif grant_type == "refresh_token":
        if not refresh_token or refresh_token not in REFRESH_TOKENS:
            raise HTTPException(status_code=400, detail="Invalid refresh token")

        token_data = REFRESH_TOKENS.pop(refresh_token)
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            raise HTTPException(status_code=400, detail="Refresh token expired")

        user = None
        for u in USERS_DB.values():
            if u["id"] == token_data["user_id"]:
                user = u
                break
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        new_access_token = create_access_token({
            "sub": user["email"],
            "name": user["name"],
            "role": user["role"],
        })
        new_refresh_token = create_refresh_token(user["id"])

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": new_refresh_token,
        }

    raise HTTPException(status_code=400, detail="Unsupported grant type")


@app.get("/oauth2/userinfo")
async def userinfo(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = auth_header[7:]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = payload.get("sub")
    user = USERS_DB.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "sub": user["email"],
        "name": user["name"],
        "email": user["email"],
        "email_verified": True,
        "role": user["role"],
    }


@app.get("/oauth2/jwks")
async def jwks():
    return {"keys": []}


# --- API Endpoints ---

@app.post("/api/token/verify")
async def verify_api_token(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse({"valid": False, "error": "Missing bearer token"}, status_code=401)

    token = auth_header[7:]
    payload = verify_token(token)
    if not payload:
        return JSONResponse({"valid": False, "error": "Invalid or expired token"}, status_code=401)

    return {"valid": True, "sub": payload.get("sub"), "role": payload.get("role"), "exp": payload.get("exp")}


@app.get("/api/roles")
async def list_roles():
    return {"roles": ROLES}
