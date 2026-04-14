import json
import os
import re
import hashlib
import hmac
import secrets
import smtplib
import sqlite3
import subprocess
import unicodedata
from functools import lru_cache
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from openai import OpenAI
from dotenv import dotenv_values
from pydantic import BaseModel

from security_utils import decrypt_json_payload, encrypt_json_payload, maybe_encrypt_legacy_json

PUBLIC_BASE_URL = os.getenv("EMAIL_SUMMARIZER_PUBLIC_BASE_URL", "").strip().rstrip("/")


def default_cors_origins() -> str:
    origins = ["http://127.0.0.1:8000", "http://localhost:8000"]
    if PUBLIC_BASE_URL:
        origins.append(PUBLIC_BASE_URL)
    return ",".join(origins)


APP_CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("EMAIL_SUMMARIZER_CORS_ORIGINS", default_cors_origins()).split(",")
    if origin.strip()
]
SESSION_COOKIE_SECURE = os.getenv("EMAIL_SUMMARIZER_COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE_DOMAIN = os.getenv("EMAIL_SUMMARIZER_COOKIE_DOMAIN", "").strip() or None

app = FastAPI(title="Email Summarizer Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=APP_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "dashboard_static"
APP_STORAGE_DIR = Path(os.getenv("EMAIL_SUMMARIZER_STORAGE_DIR", str(BASE_DIR / "data"))).resolve()
OUTPUT_ROOT_DIR = Path(os.getenv("EMAIL_SUMMARIZER_OUTPUT_DIR", str(BASE_DIR / "email_summaries_output"))).resolve()
DATA_DIR = APP_STORAGE_DIR / "users"
APP_DATA_DIR = APP_STORAGE_DIR / "app"
DB_PATH = APP_DATA_DIR / "app.db"
SESSION_COOKIE_NAME = "email_dashboard_session"
GOOGLE_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
GOOGLE_OAUTH_STATE_COOKIE = "email_dashboard_google_state"
GOOGLE_OAUTH_NEXT_COOKIE = "email_dashboard_google_next"
GOOGLE_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]
MICROSOFT_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
MICROSOFT_OAUTH_STATE_COOKIE = "email_dashboard_microsoft_state"
MICROSOFT_OAUTH_NEXT_COOKIE = "email_dashboard_microsoft_next"
MICROSOFT_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "offline_access",
    "User.Read",
]


def get_db_connection() -> sqlite3.Connection:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_db_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                google_oauth_json TEXT,
                microsoft_oauth_json TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            """
        )
        existing_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "microsoft_oauth_json" not in existing_columns:
            connection.execute("ALTER TABLE users ADD COLUMN microsoft_oauth_json TEXT")

        rows = connection.execute("SELECT user_id, settings_json, google_oauth_json, microsoft_oauth_json FROM users").fetchall()
        for row in rows:
            encrypted_settings = maybe_encrypt_legacy_json(row["settings_json"] or "{}", APP_STORAGE_DIR)
            encrypted_google = maybe_encrypt_legacy_json(row["google_oauth_json"] or "{}", APP_STORAGE_DIR)
            encrypted_microsoft = maybe_encrypt_legacy_json(row["microsoft_oauth_json"] or "{}", APP_STORAGE_DIR)
            if (
                encrypted_settings != (row["settings_json"] or "")
                or encrypted_google != (row["google_oauth_json"] or "")
                or encrypted_microsoft != (row["microsoft_oauth_json"] or "")
            ):
                connection.execute(
                    """
                    UPDATE users
                    SET settings_json = ?, google_oauth_json = ?, microsoft_oauth_json = ?
                    WHERE user_id = ?
                    """,
                    (encrypted_settings, encrypted_google, encrypted_microsoft, row["user_id"]),
                )


initialize_database()


class RunSummarizerRequest(BaseModel):
    user_id: Optional[str] = None
    days_back: int = 7


class WhitelistUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    contacts: List[str]


class ContactProfileUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    email: str
    first_name: str = ""
    last_name: str = ""


class ChatRequest(BaseModel):
    user_id: Optional[str] = None
    question: str


class CombinedSummaryRequest(BaseModel):
    user_id: Optional[str] = None
    summary_ids: List[str]


class RefineSummaryRequest(BaseModel):
    user_id: Optional[str] = None
    title: str = ""
    markdown: str
    instructions: str
    save_preference: bool = False


class SummaryStylePreferenceRequest(BaseModel):
    user_id: Optional[str] = None
    preference: str


class SignupRequest(BaseModel):
    user_id: Optional[str] = None
    email: str
    password: str


class LoginRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    password: str


class ProfileUpdateRequest(BaseModel):
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    imap_server: str = ""
    imap_port: str = "993"
    imap_user: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"
    smtp_host: str = ""
    smtp_port: str = "465"
    smtp_user: str = ""
    smtp_password: str = ""
    summary_recipient: str = ""


@app.get("/")
def home() -> RedirectResponse:
    return RedirectResponse("/login")


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.get("/health/deployment")
def deployment_health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "public_base_url_configured": bool(PUBLIC_BASE_URL),
        "cookie_secure": SESSION_COOKIE_SECURE,
        "cors_origins": APP_CORS_ORIGINS,
        "storage_dir": str(APP_STORAGE_DIR),
        "output_dir": str(OUTPUT_ROOT_DIR),
        "openai_api_key_configured": bool(get_app_config_value("OPENAI_API_KEY")),
        "google_oauth_configured": bool(get_app_config_value("GOOGLE_CLIENT_ID") and get_app_config_value("GOOGLE_CLIENT_SECRET")),
        "microsoft_oauth_configured": bool(get_app_config_value("MICROSOFT_CLIENT_ID") and get_app_config_value("MICROSOFT_CLIENT_SECRET")),
        "smtp_host_configured": bool(get_app_config_value("SMTP_HOST")),
    }


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/dashboard")
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/dashboard-preview")
def dashboard_preview() -> FileResponse:
    return FileResponse(STATIC_DIR / "preview.html")


@app.get("/dashboard-modern-preview")
def dashboard_modern_preview() -> FileResponse:
    return FileResponse(STATIC_DIR / "modern_preview.html")


@app.get("/dashboard-done-preview")
def dashboard_done_preview() -> FileResponse:
    return FileResponse(STATIC_DIR / "done_preview.html")


@app.get("/settings")
def settings_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "settings.html")


@app.get("/signup")
def signup_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "signup.html")


@app.post("/auth/signup")
def signup(request: SignupRequest, response: Response) -> Dict[str, Any]:
    email = request.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required.")
    user_id = _slugify_user_id(request.user_id) if request.user_id and request.user_id.strip() else user_id_from_email(email)
    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if load_profile(user_id):
        raise HTTPException(status_code=409, detail=f"An account for '{user_id}' already exists.")
    if find_profile_by_email(email):
        raise HTTPException(status_code=409, detail=f"An account for '{email}' already exists.")

    settings = default_profile_settings()
    try:
        settings.update(read_env_key_values(get_env_path_for_user(user_id)))
    except HTTPException:
        pass

    settings["IMAP_USER"] = settings.get("IMAP_USER") or email
    settings["IMAP_PASSWORD"] = settings.get("IMAP_PASSWORD") or request.password
    settings["SMTP_USER"] = settings.get("SMTP_USER") or email
    settings["SMTP_PASSWORD"] = settings.get("SMTP_PASSWORD") or request.password
    settings["SUMMARY_RECIPIENT"] = settings.get("SUMMARY_RECIPIENT") or email

    password_hash, password_salt = _hash_password(request.password)
    now = datetime.now().isoformat()
    profile = {
        "user_id": user_id,
        "email": email,
        "password_hash": password_hash,
        "password_salt": password_salt,
        "created_at": now,
        "updated_at": now,
        "settings": settings,
    }
    save_profile(profile)
    create_session(response, user_id)
    return {"success": True, "profile": profile_response(profile)}


@app.post("/auth/login")
def login(request: LoginRequest, response: Response) -> Dict[str, Any]:
    profile = None
    if request.email and request.email.strip():
        profile = find_profile_by_email(request.email)
    elif request.user_id and request.user_id.strip():
        profile = load_profile(_slugify_user_id(request.user_id))

    if not profile or not _verify_password(request.password, profile["password_hash"], profile["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    create_session(response, profile["user_id"])
    return {"success": True, "profile": profile_response(profile)}


@app.post("/auth/logout")
def logout(request: Request, response: Response) -> Dict[str, Any]:
    clear_session(response, request)
    return {"success": True}


@app.get("/auth/google/start")
def auth_google_start(next: str = "/dashboard") -> RedirectResponse:
    try:
        config = get_google_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?google_error=not_configured")
    state = secrets.token_urlsafe(24)
    GOOGLE_OAUTH_STATE[state] = {"next": next}
    scope = " ".join(GOOGLE_OAUTH_SCOPES)
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={quote(config['client_id'], safe='')}"
        f"&redirect_uri={quote(config['redirect_uri'], safe='')}"
        "&response_type=code"
        f"&scope={quote(scope, safe='')}"
        "&access_type=offline"
        f"&state={quote(state, safe='')}"
    )
    response = RedirectResponse(auth_url)
    response.set_cookie(
        GOOGLE_OAUTH_STATE_COOKIE,
        state,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
        path="/",
        max_age=600,
    )
    response.set_cookie(
        GOOGLE_OAUTH_NEXT_COOKIE,
        next,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
        path="/",
        max_age=600,
    )
    return response


@app.get("/auth/google/callback")
def auth_google_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None) -> RedirectResponse:
    if error:
        return RedirectResponse(f"/dashboard?google_error={quote(error, safe='')}")
    cookie_state = request.cookies.get(GOOGLE_OAUTH_STATE_COOKIE)
    if not code or not state or not cookie_state or state != cookie_state:
        return RedirectResponse("/dashboard?google_error=invalid_callback")

    config = get_google_oauth_config()
    next_url = request.cookies.get(GOOGLE_OAUTH_NEXT_COOKIE) or GOOGLE_OAUTH_STATE.pop(state, {}).get("next") or "/dashboard"

    try:
        token_payload = post_form_json(
            "https://oauth2.googleapis.com/token",
            {
                "code": code,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "redirect_uri": config["redirect_uri"],
                "grant_type": "authorization_code",
            },
        )
    except HTTPException:
        response = RedirectResponse("/dashboard?google_error=token_exchange_failed")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    access_token = token_payload.get("access_token")
    if not access_token:
        response = RedirectResponse("/dashboard?google_error=missing_access_token")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    try:
        userinfo = get_json_with_bearer("https://openidconnect.googleapis.com/v1/userinfo", access_token)
    except HTTPException:
        response = RedirectResponse("/dashboard?google_error=userinfo_failed")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    email = str(userinfo.get("email", "")).strip().lower()
    if not email:
        response = RedirectResponse("/dashboard?google_error=no_email_returned")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    profile = find_profile_by_email(email)
    if not profile:
        user_id = user_id_from_email(email)
        settings = default_profile_settings()
        settings["IMAP_USER"] = email
        settings["SMTP_USER"] = email
        settings["SUMMARY_RECIPIENT"] = email
        random_password = secrets.token_urlsafe(24)
        password_hash, password_salt = _hash_password(random_password)
        now = datetime.now().isoformat()
        profile = {
            "user_id": user_id,
            "email": email,
            "password_hash": password_hash,
            "password_salt": password_salt,
            "created_at": now,
            "updated_at": now,
            "settings": settings,
        }

    profile["google_oauth"] = {
        "provider": "google",
        "email": email,
        "access_token": token_payload.get("access_token", ""),
        "refresh_token": token_payload.get("refresh_token", ""),
        "token_type": token_payload.get("token_type", ""),
        "scope": token_payload.get("scope", ""),
        "expires_in": token_payload.get("expires_in", 0),
        "id_token": token_payload.get("id_token", ""),
        "updated_at": datetime.now().isoformat(),
    }
    save_profile(profile)

    response = RedirectResponse(next_url)
    create_session(response, profile["user_id"])
    response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    return response


@app.get("/auth/microsoft/start")
def auth_microsoft_start(next: str = "/dashboard") -> RedirectResponse:
    try:
        config = get_microsoft_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?microsoft_error=not_configured")

    state = secrets.token_urlsafe(24)
    MICROSOFT_OAUTH_STATE[state] = {"next": next}
    scope = " ".join(MICROSOFT_OAUTH_SCOPES)
    auth_url = (
        f"https://login.microsoftonline.com/{quote(config['tenant'], safe='')}/oauth2/v2.0/authorize"
        f"?client_id={quote(config['client_id'], safe='')}"
        "&response_type=code"
        f"&redirect_uri={quote(config['redirect_uri'], safe='')}"
        "&response_mode=query"
        f"&scope={quote(scope, safe='')}"
        f"&state={quote(state, safe='')}"
    )
    response = RedirectResponse(auth_url)
    response.set_cookie(
        MICROSOFT_OAUTH_STATE_COOKIE,
        state,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
        path="/",
        max_age=600,
    )
    response.set_cookie(
        MICROSOFT_OAUTH_NEXT_COOKIE,
        next,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
        path="/",
        max_age=600,
    )
    return response


@app.get("/auth/microsoft/callback")
def auth_microsoft_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None) -> RedirectResponse:
    if error:
        return RedirectResponse(f"/dashboard?microsoft_error={quote(error, safe='')}")

    cookie_state = request.cookies.get(MICROSOFT_OAUTH_STATE_COOKIE)
    if not code or not state or not cookie_state or state != cookie_state:
        return RedirectResponse("/dashboard?microsoft_error=invalid_callback")

    config = get_microsoft_oauth_config()
    next_url = request.cookies.get(MICROSOFT_OAUTH_NEXT_COOKIE) or MICROSOFT_OAUTH_STATE.pop(state, {}).get("next") or "/dashboard"
    token_url = f"https://login.microsoftonline.com/{config['tenant']}/oauth2/v2.0/token"

    try:
        token_payload = post_form_json(
            token_url,
            {
                "code": code,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "redirect_uri": config["redirect_uri"],
                "grant_type": "authorization_code",
                "scope": " ".join(MICROSOFT_OAUTH_SCOPES),
            },
            error_prefix="Microsoft token exchange failed",
        )
    except HTTPException:
        response = RedirectResponse("/dashboard?microsoft_error=token_exchange_failed")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    access_token = token_payload.get("access_token")
    if not access_token:
        response = RedirectResponse("/dashboard?microsoft_error=missing_access_token")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    try:
        userinfo = get_json_with_bearer(
            "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName,displayName",
            access_token,
            error_prefix="Microsoft userinfo request failed",
        )
    except HTTPException:
        response = RedirectResponse("/dashboard?microsoft_error=userinfo_failed")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    email = str(userinfo.get("mail") or userinfo.get("userPrincipalName") or "").strip().lower()
    if not email:
        response = RedirectResponse("/dashboard?microsoft_error=no_email_returned")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    profile = find_profile_by_email(email)
    if not profile:
        user_id = user_id_from_email(email)
        settings = default_profile_settings()
        settings["IMAP_USER"] = email
        settings["SMTP_USER"] = email
        settings["SUMMARY_RECIPIENT"] = email
        random_password = secrets.token_urlsafe(24)
        password_hash, password_salt = _hash_password(random_password)
        now = datetime.now().isoformat()
        profile = {
            "user_id": user_id,
            "email": email,
            "password_hash": password_hash,
            "password_salt": password_salt,
            "created_at": now,
            "updated_at": now,
            "settings": settings,
        }

    profile["microsoft_oauth"] = {
        "provider": "microsoft",
        "email": email,
        "display_name": str(userinfo.get("displayName", "")).strip(),
        "access_token": token_payload.get("access_token", ""),
        "refresh_token": token_payload.get("refresh_token", ""),
        "token_type": token_payload.get("token_type", ""),
        "scope": token_payload.get("scope", ""),
        "expires_in": token_payload.get("expires_in", 0),
        "id_token": token_payload.get("id_token", ""),
        "updated_at": datetime.now().isoformat(),
    }
    save_profile(profile)

    response = RedirectResponse(next_url)
    create_session(response, profile["user_id"])
    response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    return response


@app.get("/auth/me")
def auth_me(request: Request) -> Dict[str, Any]:
    user_id = get_session_user_id(request)
    if not user_id:
        return {"authenticated": False}

    profile = load_profile(user_id)
    if not profile:
        return {"authenticated": False}

    return {"authenticated": True, "profile": profile_response(profile)}


@app.get("/profile")
def get_profile(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    return {"profile": profile_response(profile)}


@app.put("/profile")
def update_profile(request: Request, payload: ProfileUpdateRequest, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    profile["email"] = payload.email.strip()
    profile["settings"] = profile_update_to_settings(payload, {**default_profile_settings(), **(profile.get("settings") or {})})
    save_profile(profile)
    return {"success": True, "profile": profile_response(profile)}


def _slugify_user_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "", value.strip()) or "user"


def user_id_from_email(email: str) -> str:
    lowered = email.strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", lowered).strip("_") or "user"


def get_profile_path_for_user(user_id: str) -> Path:
    return DATA_DIR / user_id / "profile.json"


def get_app_config_value(key: str) -> str:
    value = os.getenv(key)
    if value:
        return value

    for candidate in (BASE_DIR / ".env.google_oauth", BASE_DIR / ".env"):
        if candidate.exists():
            parsed = dotenv_values(candidate)
            maybe = parsed.get(key)
            if maybe:
                return str(maybe)
    return ""


def get_google_oauth_config() -> Dict[str, str]:
    client_id = get_app_config_value("GOOGLE_CLIENT_ID")
    client_secret = get_app_config_value("GOOGLE_CLIENT_SECRET")
    redirect_uri = get_app_config_value("GOOGLE_REDIRECT_URI") or (
        f"{PUBLIC_BASE_URL}/auth/google/callback" if PUBLIC_BASE_URL else "http://127.0.0.1:8000/auth/google/callback"
    )
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first.",
        )
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }


def get_microsoft_oauth_config() -> Dict[str, str]:
    client_id = get_app_config_value("MICROSOFT_CLIENT_ID")
    client_secret = get_app_config_value("MICROSOFT_CLIENT_SECRET")
    tenant = get_app_config_value("MICROSOFT_TENANT_ID") or "common"
    redirect_uri = get_app_config_value("MICROSOFT_REDIRECT_URI") or (
        f"{PUBLIC_BASE_URL}/auth/microsoft/callback" if PUBLIC_BASE_URL else "http://127.0.0.1:8000/auth/microsoft/callback"
    )
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=500,
            detail="Microsoft OAuth is not configured yet. Add MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET first.",
        )
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "tenant": tenant,
        "redirect_uri": redirect_uri,
    }


def post_form_json(url: str, data: Dict[str, str], error_prefix: str = "OAuth token exchange failed") -> Dict[str, Any]:
    body = "&".join(f"{quote(str(key), safe='')}={quote(str(value), safe='')}" for key, value in data.items()).encode("utf-8")
    request = UrlRequest(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"{error_prefix}: {payload}") from exc


def get_json_with_bearer(url: str, access_token: str, error_prefix: str = "OAuth userinfo request failed") -> Dict[str, Any]:
    request = UrlRequest(url, headers={"Authorization": f"Bearer {access_token}"}, method="GET")
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"{error_prefix}: {payload}") from exc


def default_profile_settings() -> Dict[str, str]:
    settings = {
        "FIRST_NAME": "",
        "LAST_NAME": "",
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "OPENAI_MODEL": os.getenv("OPENAI_MODEL", "gpt-4o"),
        "WHITELIST_SENDERS": "",
        "CONTACT_PROFILES": "{}",
        "MAILBOX_CONNECTION_CONFIRMED": "false",
        "SUMMARY_STYLE_PREFERENCES": "[]",
        "IMAP_SERVER": os.getenv("IMAP_SERVER", ""),
        "IMAP_PORT": os.getenv("IMAP_PORT", "993"),
        "IMAP_USER": os.getenv("IMAP_USER", ""),
        "IMAP_PASSWORD": os.getenv("IMAP_PASSWORD", ""),
        "IMAP_FOLDER": os.getenv("IMAP_FOLDER", "INBOX"),
        "SMTP_HOST": os.getenv("SMTP_HOST", ""),
        "SMTP_PORT": os.getenv("SMTP_PORT", "465"),
        "SMTP_USER": os.getenv("SMTP_USER", ""),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", ""),
        "SUMMARY_RECIPIENT": os.getenv("SUMMARY_RECIPIENT", ""),
    }
    base_env = BASE_DIR / ".env"
    if base_env.exists():
        env_values = read_env_key_values(base_env)
        for key, value in env_values.items():
            if not settings.get(key):
                settings[key] = value
    return settings


def parse_summary_style_preferences(settings_or_raw: Any) -> List[str]:
    if isinstance(settings_or_raw, dict):
        raw = str(settings_or_raw.get("SUMMARY_STYLE_PREFERENCES", "") or "").strip()
    else:
        raw = str(settings_or_raw or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in raw.split("\n") if item.strip()]


def parse_contact_profiles(settings_or_raw: Any) -> Dict[str, Dict[str, str]]:
    if isinstance(settings_or_raw, dict):
        raw = str(settings_or_raw.get("CONTACT_PROFILES", "") or "").strip()
    else:
        raw = str(settings_or_raw or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}

    normalized: Dict[str, Dict[str, str]] = {}
    for email, value in parsed.items():
        email_text = str(email or "").strip().lower()
        if not email_text:
            continue
        payload = value if isinstance(value, dict) else {}
        normalized[email_text] = {
            "first_name": str(payload.get("first_name", "") or "").strip(),
            "last_name": str(payload.get("last_name", "") or "").strip(),
        }
    return normalized


def encode_contact_profiles(profiles: Dict[str, Dict[str, str]]) -> str:
    cleaned: Dict[str, Dict[str, str]] = {}
    for email, payload in (profiles or {}).items():
        email_text = str(email or "").strip().lower()
        if not email_text:
            continue
        first_name = str((payload or {}).get("first_name", "") or "").strip()
        last_name = str((payload or {}).get("last_name", "") or "").strip()
        if not first_name and not last_name:
            continue
        cleaned[email_text] = {
            "first_name": first_name,
            "last_name": last_name,
        }
    return json.dumps(cleaned, sort_keys=True)


def contact_profile_display_name(profile: Dict[str, str]) -> str:
    return " ".join(
        part for part in [str(profile.get("first_name", "")).strip(), str(profile.get("last_name", "")).strip()]
        if part
    ).strip()


def contact_label_for_email(email: str, profiles: Dict[str, Dict[str, str]]) -> str:
    normalized_email = str(email or "").strip().lower()
    profile = profiles.get(normalized_email, {})
    display_name = contact_profile_display_name(profile)
    if display_name:
        return f"{display_name} ({normalized_email})"
    return normalized_email


def build_contact_profile_items(settings: Dict[str, str]) -> List[Dict[str, str]]:
    contacts = [item.strip().lower() for item in str(settings.get("WHITELIST_SENDERS", "") or "").split(",") if item.strip()]
    profiles = parse_contact_profiles(settings)
    items: List[Dict[str, str]] = []
    for email in contacts:
        profile = profiles.get(email, {})
        first_name = str(profile.get("first_name", "") or "").strip()
        last_name = str(profile.get("last_name", "") or "").strip()
        full_name = contact_profile_display_name(profile)
        items.append(
            {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "full_name": full_name,
                "label": f"{full_name} ({email})" if full_name else email,
            }
        )
    return items


def encode_summary_style_preferences(preferences: List[str]) -> str:
    cleaned: List[str] = []
    seen = set()
    for preference in preferences:
        text = str(preference).strip()
        lowered = text.lower()
        if not text or lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)
    return json.dumps(cleaned)


def add_summary_style_preference(user_id: str, preference: str) -> List[str]:
    profile = load_profile_or_404(user_id)
    settings = merge_non_empty_settings(default_profile_settings(), profile.get("settings") or {})
    preferences = parse_summary_style_preferences(settings)
    preferences.append(preference)
    settings["SUMMARY_STYLE_PREFERENCES"] = encode_summary_style_preferences(preferences)
    profile["settings"] = settings
    save_profile(profile)
    return parse_summary_style_preferences(settings)


def remove_summary_style_preference(user_id: str, preference: str) -> List[str]:
    profile = load_profile_or_404(user_id)
    settings = merge_non_empty_settings(default_profile_settings(), profile.get("settings") or {})
    target = preference.strip().lower()
    preferences = [
        item for item in parse_summary_style_preferences(settings)
        if item.strip().lower() != target
    ]
    settings["SUMMARY_STYLE_PREFERENCES"] = encode_summary_style_preferences(preferences)
    profile["settings"] = settings
    save_profile(profile)
    return preferences


def profile_settings_to_response(settings: Dict[str, str]) -> Dict[str, str]:
    return {
        "first_name": settings.get("FIRST_NAME", ""),
        "last_name": settings.get("LAST_NAME", ""),
        "openai_model": settings.get("OPENAI_MODEL", "gpt-4o"),
        "summary_style_preferences": parse_summary_style_preferences(settings),
        "imap_user": settings.get("IMAP_USER", ""),
        "imap_server": settings.get("IMAP_SERVER", ""),
        "imap_port": settings.get("IMAP_PORT", ""),
        "mailbox_connected": str(settings.get("MAILBOX_CONNECTION_CONFIRMED", "false")).lower() == "true",
    }


def profile_update_to_settings(update: ProfileUpdateRequest, existing: Dict[str, str]) -> Dict[str, str]:
    settings = dict(existing)
    settings["FIRST_NAME"] = update.first_name.strip()
    settings["LAST_NAME"] = update.last_name.strip()
    if update.imap_user.strip():
        settings["IMAP_USER"] = update.imap_user.strip()
    if update.email.strip():
        settings["SUMMARY_RECIPIENT"] = update.email.strip()
        settings["SMTP_USER"] = settings.get("SMTP_USER") or update.email.strip()
    if update.imap_password:
        settings["IMAP_PASSWORD"] = update.imap_password
        settings["SMTP_PASSWORD"] = settings.get("SMTP_PASSWORD") or update.imap_password
        settings["MAILBOX_CONNECTION_CONFIRMED"] = "true"
    return settings


def merge_non_empty_settings(base: Dict[str, str], overrides: Dict[str, Any]) -> Dict[str, str]:
    merged = dict(base)
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        value_str = str(value)
        if value_str.strip() == "":
            continue
        merged[str(key)] = value_str
    return merged


def apply_provider_defaults(settings: Dict[str, str], email: str) -> Dict[str, str]:
    normalized = (email or "").strip().lower()
    merged = dict(settings)
    provider_defaults = None

    if normalized.endswith("@gmail.com"):
        provider_defaults = {
            "IMAP_SERVER": "imap.gmail.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif normalized.endswith(("@outlook.com", "@hotmail.com", "@live.com", "@msn.com")):
        provider_defaults = {
            "IMAP_SERVER": "outlook.office365.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp-mail.outlook.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif normalized.endswith(("@yahoo.com", "@ymail.com")):
        provider_defaults = {
            "IMAP_SERVER": "imap.mail.yahoo.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp.mail.yahoo.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif normalized.endswith("@icloud.com"):
        provider_defaults = {
            "IMAP_SERVER": "imap.mail.me.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp.mail.me.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif normalized.endswith("@263.net") or normalized.endswith("@263.com"):
        provider_defaults = {
            "IMAP_SERVER": "imap.263.net",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp.263.net",
            "SMTP_PORT": "465",
            "IMAP_FOLDER": "INBOX",
        }

    if provider_defaults:
        for key, value in provider_defaults.items():
            if not merged.get(key):
                merged[key] = value
    return merged


def row_to_profile(row: sqlite3.Row) -> Dict[str, Any]:
    settings = merge_non_empty_settings(
        default_profile_settings(),
        decrypt_json_payload(row["settings_json"] or "{}", APP_STORAGE_DIR),
    )
    settings = apply_provider_defaults(settings, row["email"])
    google_oauth = decrypt_json_payload(row["google_oauth_json"] or "{}", APP_STORAGE_DIR)
    microsoft_oauth = decrypt_json_payload(row["microsoft_oauth_json"] or "{}", APP_STORAGE_DIR)
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "password_salt": row["password_salt"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "settings": settings,
        "google_oauth": google_oauth,
        "microsoft_oauth": microsoft_oauth,
    }


def migrate_profile_json_to_db(user_id: str) -> Optional[Dict[str, Any]]:
    profile_path = get_profile_path_for_user(user_id)
    if not profile_path.exists():
        return None
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    payload["settings"] = merge_non_empty_settings(default_profile_settings(), payload.get("settings") or {})
    payload["settings"] = apply_provider_defaults(payload["settings"], payload.get("email", ""))
    save_profile(payload)
    return payload


def load_profile(user_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return row_to_profile(row)
    return migrate_profile_json_to_db(user_id)


def find_profile_by_email(email: str) -> Optional[Dict[str, Any]]:
    normalized = email.strip().lower()
    if not normalized:
        return None
    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE lower(email) = ?", (normalized,)).fetchone()
    if row:
        return row_to_profile(row)
    for profile_path in DATA_DIR.glob("*/profile.json"):
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
        if str(payload.get("email", "")).strip().lower() == normalized:
            payload["settings"] = {**default_profile_settings(), **(payload.get("settings") or {})}
            save_profile(payload)
            return payload
    return None


def load_profile_or_404(user_id: str) -> Dict[str, Any]:
    profile = load_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No profile found for user '{user_id}'.")
    return profile


def save_profile(profile: Dict[str, Any]) -> None:
    profile["updated_at"] = datetime.now().isoformat()
    profile.setdefault("created_at", profile["updated_at"])
    settings_json = encrypt_json_payload(profile.get("settings") or {}, APP_STORAGE_DIR)
    google_oauth_json = encrypt_json_payload(profile.get("google_oauth") or {}, APP_STORAGE_DIR)
    microsoft_oauth_json = encrypt_json_payload(profile.get("microsoft_oauth") or {}, APP_STORAGE_DIR)

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO users (user_id, email, password_hash, password_salt, created_at, updated_at, settings_json, google_oauth_json, microsoft_oauth_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                email = excluded.email,
                password_hash = excluded.password_hash,
                password_salt = excluded.password_salt,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at,
                settings_json = excluded.settings_json,
                google_oauth_json = excluded.google_oauth_json,
                microsoft_oauth_json = excluded.microsoft_oauth_json
            """,
            (
                profile["user_id"],
                profile["email"],
                profile["password_hash"],
                profile["password_salt"],
                profile["created_at"],
                profile["updated_at"],
                settings_json,
                google_oauth_json,
                microsoft_oauth_json,
            ),
        )


def profile_response(profile: Dict[str, Any]) -> Dict[str, Any]:
    settings = profile.get("settings") or {}
    contacts = [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
    contact_profiles = build_contact_profile_items(settings)
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    microsoft_connected = bool((profile.get("microsoft_oauth") or {}).get("refresh_token") or (profile.get("microsoft_oauth") or {}).get("access_token"))
    auth_provider = "google" if google_connected else "microsoft" if microsoft_connected else "password"
    return {
        "user_id": profile["user_id"],
        "email": profile.get("email", ""),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "contacts": contacts,
        "contact_profiles": contact_profiles,
        "google_connected": google_connected,
        "microsoft_connected": microsoft_connected,
        "auth_provider": auth_provider,
        "settings": profile_settings_to_response(settings),
    }


def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000,
    ).hex()
    return password_hash, salt


def _verify_password(password: str, password_hash: str, salt: str) -> bool:
    computed_hash, _ = _hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)


def create_session(response: Response, user_id: str) -> str:
    session_token = secrets.token_urlsafe(32)
    with get_db_connection() as connection:
        connection.execute(
            "INSERT INTO sessions (session_token, user_id, created_at) VALUES (?, ?, ?)",
            (session_token, user_id, datetime.now().isoformat()),
        )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
    )
    return session_token


def clear_session(response: Response, request: Request) -> None:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        with get_db_connection() as connection:
            connection.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    response.delete_cookie(SESSION_COOKIE_NAME, domain=SESSION_COOKIE_DOMAIN)


def get_session_user_id(request: Request) -> Optional[str]:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None
    with get_db_connection() as connection:
        row = connection.execute("SELECT user_id FROM sessions WHERE session_token = ?", (session_token,)).fetchone()
    if not row:
        return None
    return str(row["user_id"])


def resolve_user_id(request: Request, explicit_user_id: Optional[str] = None) -> str:
    session_user_id = get_session_user_id(request)
    explicit = explicit_user_id.strip() if explicit_user_id and explicit_user_id.strip() else None

    if explicit and not session_user_id:
        raise HTTPException(status_code=401, detail="Please log in first.")
    if explicit and session_user_id and explicit != session_user_id:
        raise HTTPException(status_code=403, detail="You do not have access to that user.")
    if explicit:
        return explicit
    if session_user_id:
        return session_user_id

    raise HTTPException(status_code=401, detail="Please log in first.")


def get_env_path_for_user(user_id: str) -> Path:
    if user_id == "default":
        path = BASE_DIR / ".env"
    else:
        path = BASE_DIR / f".env.{user_id}"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"No .env file found for user '{user_id}'.")
    return path


def read_env_key_values(env_path: Path) -> Dict[str, str]:
    parsed = dotenv_values(env_path)
    return {str(key): str(value) for key, value in parsed.items() if key and value is not None}


def write_env_key(env_path: Path, key: str, value: str) -> None:
    lines = env_path.read_text(encoding="utf-8").splitlines()
    updated = False
    new_lines: List[str] = []

    for line in lines:
        if line.strip().startswith(f"{key}="):
            new_lines.append(f"{key}={value}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines.append(f"{key}={value}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def get_settings_for_user(user_id: str) -> Dict[str, str]:
    profile = load_profile(user_id)
    if profile:
        return {**default_profile_settings(), **(profile.get("settings") or {})}

    env_path = get_env_path_for_user(user_id)
    return {**default_profile_settings(), **read_env_key_values(env_path)}


def get_contacts_for_user(user_id: str) -> List[str]:
    settings = get_settings_for_user(user_id)
    return [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]


def set_contacts_for_user(user_id: str, contacts: List[str]) -> None:
    cleaned_contacts: List[str] = []
    seen = set()
    for contact in contacts:
        email = str(contact or "").strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        cleaned_contacts.append(email)
    profile = load_profile(user_id)
    if profile:
        profile["settings"] = {**default_profile_settings(), **(profile.get("settings") or {})}
        profile["settings"]["WHITELIST_SENDERS"] = ",".join(cleaned_contacts)
        existing_profiles = parse_contact_profiles(profile["settings"])
        profile["settings"]["CONTACT_PROFILES"] = encode_contact_profiles(
            {email: existing_profiles[email] for email in cleaned_contacts if email in existing_profiles}
        )
        save_profile(profile)
        return

    env_path = get_env_path_for_user(user_id)
    write_env_key(env_path, "WHITELIST_SENDERS", ",".join(cleaned_contacts))


@app.get("/users")
def list_available_users() -> Dict[str, Any]:
    users = []
    seen_user_ids = set()

    with get_db_connection() as connection:
        rows = connection.execute("SELECT * FROM users ORDER BY lower(email)").fetchall()

    for row in rows:
        profile = row_to_profile(row)
        settings = profile.get("settings") or {}
        contacts = [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
        users.append(
            {
                "user_id": profile.get("user_id"),
                "source": "profile",
                "email": profile.get("email", ""),
                "whitelist_contacts": contacts,
            }
        )
        seen_user_ids.add(profile.get("user_id"))

    for option in sorted(BASE_DIR.glob(".env*")):
        if option.name == ".env":
            label = "default"
        elif option.name.startswith(".env."):
            label = option.name.replace(".env.", "")
        else:
            continue
        if label in seen_user_ids:
            continue
        env_values = read_env_key_values(option)
        whitelist = [item.strip() for item in env_values.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
        users.append({"user_id": label, "source": "env", "env_file": option.name, "whitelist_contacts": whitelist})
    return {"users": users}


@app.get("/whitelist")
def get_whitelist(request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile(resolved_user_id)
    settings = profile.get("settings") if profile else get_settings_for_user(resolved_user_id)
    contacts = [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
    source = "profile" if profile else "env"
    return {
        "user_id": resolved_user_id,
        "contacts": contacts,
        "contact_profiles": build_contact_profile_items(settings),
        "source": source,
    }


@app.post("/whitelist")
def update_whitelist(payload: WhitelistUpdateRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    cleaned_contacts = [contact.strip() for contact in payload.contacts if contact.strip()]
    set_contacts_for_user(resolved_user_id, cleaned_contacts)
    settings = get_settings_for_user(resolved_user_id)
    return {
        "user_id": resolved_user_id,
        "contacts": [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()],
        "contact_profiles": build_contact_profile_items(settings),
        "success": True,
    }


@app.post("/contacts/profile")
def update_contact_profile(payload: ContactProfileUpdateRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    email = payload.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Contact email is required.")

    profile = load_profile_or_404(resolved_user_id)
    profile["settings"] = {**default_profile_settings(), **(profile.get("settings") or {})}
    contacts = [item.strip().lower() for item in profile["settings"].get("WHITELIST_SENDERS", "").split(",") if item.strip()]
    if email not in contacts:
        raise HTTPException(status_code=404, detail="That contact is not in the current contact list.")

    contact_profiles = parse_contact_profiles(profile["settings"])
    first_name = payload.first_name.strip()
    last_name = payload.last_name.strip()
    if first_name or last_name:
        contact_profiles[email] = {
            "first_name": first_name,
            "last_name": last_name,
        }
    else:
        contact_profiles.pop(email, None)
    profile["settings"]["CONTACT_PROFILES"] = encode_contact_profiles(contact_profiles)
    save_profile(profile)
    return {
        "success": True,
        "user_id": resolved_user_id,
        "contact_profiles": build_contact_profile_items(profile["settings"]),
    }


def get_user_summaries_dir(user_id: str) -> Path:
    return OUTPUT_ROOT_DIR / user_id / "summaries"


def get_user_json_summaries_dir(user_id: str) -> Path:
    return DATA_DIR / user_id / "summaries"


def get_user_json_emails_dir(user_id: str) -> Path:
    return DATA_DIR / user_id / "emails"


def get_user_processed_state_path(user_id: str) -> Path:
    return OUTPUT_ROOT_DIR / user_id / "processed_state.json"


def extract_markdown_title(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return fallback


def extract_markdown_section(content: str, section_name: str) -> str:
    lines = content.splitlines()
    target_header = f"## {section_name}".strip().lower()
    collecting = False
    collected: List[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.lower() == target_header:
            collecting = True
            continue
        if collecting and stripped.startswith("## "):
            break
        if collecting:
            collected.append(line)

    return "\n".join(collected).strip()


def summarize_preview(content: str) -> str:
    executive_summary = extract_markdown_section(content, "Executive Summary")
    if executive_summary:
        return executive_summary[:280]

    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
    if not lines:
        return ""
    return lines[0][:280]


@lru_cache(maxsize=512)
def read_text_cached(path_str: str, mtime_ns: int, size: int) -> str:
    return Path(path_str).read_text(encoding="utf-8")


def load_summary_file(summary_path: Path) -> Dict[str, Any]:
    stat = summary_path.stat()
    content = read_text_cached(str(summary_path), stat.st_mtime_ns, stat.st_size)

    return {
        "summary_id": summary_path.stem,
        "user_id": summary_path.parent.parent.name,
        "filename": summary_path.name,
        "title": extract_markdown_title(content, summary_path.stem),
        "preview": summarize_preview(content),
        "content_markdown": content,
        "executive_summary": extract_markdown_section(content, "Executive Summary"),
        "action_items": extract_markdown_section(content, "Action Items / Asks"),
        "deadlines": extract_markdown_section(content, "Deadlines / Dates / Meetings"),
        "bottom_line": extract_markdown_section(content, "Bottom Line"),
        "updated_at": stat.st_mtime,
    }


def load_summary_json(summary_path: Path) -> Dict[str, Any]:
    stat = summary_path.stat()
    payload = json.loads(read_text_cached(str(summary_path), stat.st_mtime_ns, stat.st_size))
    payload.setdefault("summary_id", summary_path.stem)
    payload.setdefault("user_id", summary_path.parent.parent.name)
    payload.setdefault("filename", summary_path.name)
    payload.setdefault("preview", payload.get("executive_summary") or payload.get("bottom_line") or "")
    payload.setdefault("updated_at", payload.get("created_at") or stat.st_mtime)
    return payload


def apply_contact_profile_to_summary(summary: Dict[str, Any], profiles: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    sender = str(summary.get("sender", "") or "").strip().lower()
    if not sender:
        return summary
    profile = profiles.get(sender)
    if not profile:
        return summary

    full_name = contact_profile_display_name(profile)
    if not full_name:
        return summary

    updated = dict(summary)
    updated["contact_label"] = f"{full_name} ({sender})"
    raw_title = str(updated.get("title", "") or "").strip()
    if raw_title:
        updated["title"] = re.sub(
            r"^(Email Summary\s+[—-]\s+)?(.+?)\s+\(([^)]+)\)$",
            lambda match: f"{match.group(1) or ''}{full_name} ({match.group(3)})",
            raw_title,
            count=1,
        )
    return updated


def load_summary_json_preview(summary_path: Path) -> Dict[str, Any]:
    payload = load_summary_json(summary_path)
    return {
        "summary_id": payload.get("summary_id", summary_path.stem),
        "user_id": payload.get("user_id", summary_path.parent.parent.name),
        "filename": payload.get("filename", summary_path.name),
        "sender": payload.get("sender", ""),
        "contact_label": payload.get("contact_label", ""),
        "title": payload.get("title", summary_path.stem),
        "preview": payload.get("preview", ""),
        "updated_at": payload.get("updated_at"),
    }


def load_processed_uids_for_user(user_id: str) -> List[str]:
    path = get_user_processed_state_path(user_id)
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [str(uid).strip() for uid in payload.get("processed_uids", []) if str(uid).strip()]


def save_processed_uids_for_user(user_id: str, uids: List[str]) -> None:
    path = get_user_processed_state_path(user_id)
    payload = {
        "processed_uids": sorted(set(str(uid).strip() for uid in uids if str(uid).strip())),
        "last_run": __import__("datetime").datetime.now().isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def get_chat_ready_summaries(user_id: str) -> List[Dict[str, Any]]:
    summaries_dir = get_user_json_summaries_dir(user_id)
    if not summaries_dir.exists():
        return []

    summary_files = sorted(summaries_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    summaries = [load_summary_json(path) for path in summary_files]

    contact_summaries = [s for s in summaries if not str(s.get("summary_id", "")).startswith("overall_master_")]
    return contact_summaries or summaries


def load_email_json(email_path: Path) -> Dict[str, Any]:
    stat = email_path.stat()
    payload = json.loads(read_text_cached(str(email_path), stat.st_mtime_ns, stat.st_size))
    payload.setdefault("email_id", email_path.stem)
    return payload


def get_chat_ready_emails(user_id: str, summaries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    emails_dir = get_user_json_emails_dir(user_id)
    if not emails_dir.exists():
        return []

    seen_ids = set()
    email_ids: List[str] = []
    for summary in summaries:
        for email_id in summary.get("source_email_file_ids", []) or []:
            if email_id and email_id not in seen_ids:
                seen_ids.add(email_id)
                email_ids.append(email_id)

    emails: List[Dict[str, Any]] = []
    for email_id in email_ids:
        email_path = emails_dir / f"{email_id}.json"
        if email_path.exists():
            emails.append(load_email_json(email_path))
    return emails


def find_attachment_matches(user_id: str, emails: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    query_lower = query.lower().strip()
    if not query_lower:
        return []

    matches: List[Dict[str, Any]] = []
    seen_paths = set()
    stopwords = {"show", "open", "display", "pull", "bring", "view", "download", "file", "attachment", "the", "me", "can", "you", "pdf"}
    query_tokens = [
        token for token in re.split(r"[^a-zA-Z0-9._-]+", query_lower)
        if len(token) >= 3 and token not in stopwords
    ]

    for email_record in emails:
        for message in email_record.get("thread", []):
            for attachment in message.get("attachments", []):
                filename = attachment.get("filename", "")
                saved_path = attachment.get("saved_path", "")
                if not filename or not saved_path:
                    continue
                filename_lower = filename.lower()
                exact_name_match = filename_lower in query_lower or query_lower in filename_lower
                token_hits = sum(1 for token in query_tokens if token in filename_lower)
                token_match = token_hits >= min(2, len(query_tokens)) if query_tokens else False
                if not exact_name_match and not token_match:
                    continue

                resolved_path = (BASE_DIR / saved_path).resolve()
                try:
                    resolved_path.relative_to(BASE_DIR.resolve())
                except ValueError:
                    continue
                if not resolved_path.exists() or str(resolved_path) in seen_paths:
                    continue

                seen_paths.add(str(resolved_path))
                matches.append(
                    {
                        "filename": filename,
                        "message_id": message.get("message_id", ""),
                        "date": message.get("date", ""),
                        "url": f"/attachments?user_id={user_id}&path={saved_path}",
                    }
                )
    return matches


def _compact_for_chat(text: str, max_chars: int) -> str:
    text = (text or "").strip()
    if len(text) > max_chars:
        return text[:max_chars] + "\n... [truncated]"
    return text


def _to_ascii_safe(text: str) -> str:
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2192": "->",
        "\u2190": "<-",
        "\u2022": "*",
        "\u00a0": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


@app.get("/attachments")
def get_attachment(request: Request, user_id: str = Query(...), path: str = Query(...)) -> FileResponse:
    resolved_user_id = resolve_user_id(request, user_id)
    requested_path = Path(path).resolve() if Path(path).is_absolute() else (BASE_DIR / path).resolve()
    allowed_roots = [
        (OUTPUT_ROOT_DIR / resolved_user_id).resolve(),
        (APP_STORAGE_DIR / "users" / resolved_user_id).resolve(),
    ]
    if not any(
        requested_path == root or requested_path.is_relative_to(root)
        for root in allowed_roots
    ):
        raise HTTPException(status_code=403, detail="You do not have access to that attachment.")

    if not requested_path.exists() or not requested_path.is_file():
        raise HTTPException(status_code=404, detail=f"Attachment not found for user '{resolved_user_id}'.")

    return FileResponse(requested_path, filename=requested_path.name)


@app.delete("/summaries/{summary_id}")
def delete_summary(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    summary_payload = load_summary_json(summary_path)
    other_summaries = [
        load_summary_json(path)
        for path in get_user_json_summaries_dir(user_id).glob("*.json")
        if path.name != summary_path.name
    ]

    removed_email_ids: List[str] = []
    removed_uids: List[str] = []
    for email_id in summary_payload.get("source_email_file_ids", []) or []:
        if any(email_id in (other.get("source_email_file_ids", []) or []) for other in other_summaries):
            continue

        email_path = get_user_json_emails_dir(user_id) / f"{email_id}.json"
        if not email_path.exists():
            continue
        email_payload = load_email_json(email_path)
        if email_payload.get("uid") is not None:
            removed_uids.append(str(email_payload["uid"]).strip())
        email_path.unlink()
        removed_email_ids.append(email_id)

    summary_path.unlink()

    if removed_uids:
        remaining_uids = [uid for uid in load_processed_uids_for_user(user_id) if uid not in set(removed_uids)]
        save_processed_uids_for_user(user_id, remaining_uids)

    return {
        "success": True,
        "user_id": user_id,
        "summary_id": summary_id,
        "removed_email_ids": removed_email_ids,
        "removed_uids": removed_uids,
    }


def build_chat_context(
    user_id: str,
    summaries: List[Dict[str, Any]],
    emails: List[Dict[str, Any]],
    max_total_chars: int = 90000,
) -> str:
    blocks: List[str] = []
    total_chars = 0

    for summary in summaries:
        parts = [
            f"Summary ID: {summary.get('summary_id', '')}",
            f"Title: {summary.get('title', '')}",
            f"Run Date: {summary.get('run_date_display') or summary.get('run_date', '')}",
        ]

        if summary.get("contact_label"):
            parts.append(f"Contact: {summary['contact_label']}")
        if summary.get("executive_summary"):
            parts.append("Executive Summary:\n" + _compact_for_chat(summary["executive_summary"], 1200))
        if summary.get("main_topics"):
            parts.append("Main Topics:\n" + _compact_for_chat(summary["main_topics"], 900))
        if summary.get("new_developments"):
            parts.append("New Developments:\n" + _compact_for_chat(summary["new_developments"], 900))
        if summary.get("action_items"):
            parts.append("Action Items:\n" + _compact_for_chat(summary["action_items"], 900))
        if summary.get("deadlines"):
            parts.append("Deadlines:\n" + _compact_for_chat(summary["deadlines"], 700))
        if summary.get("risks"):
            parts.append("Risks:\n" + _compact_for_chat(summary["risks"], 700))
        if summary.get("bottom_line"):
            parts.append("Bottom Line:\n" + _compact_for_chat(summary["bottom_line"], 700))

        block = _to_ascii_safe("\n".join(parts))
        if total_chars + len(block) > max_total_chars and blocks:
            break
        blocks.append(block)
        total_chars += len(block) + 2

    for email_record in emails:
        thread_blocks: List[str] = [
            f"Email Record: {email_record.get('email_id', '')}",
            f"Top-level Subject: {email_record.get('subject', '')}",
            f"Top-level Sender: {email_record.get('sender', '')}",
            f"Top-level Date: {email_record.get('date', '')}",
        ]

        for idx, message in enumerate(email_record.get("thread", [])[:8], start=1):
            body = _compact_for_chat(message.get("body", ""), 1200)
            message_block = [
                f"Message {idx}",
                f"From: {message.get('sender', '')}",
                f"Date: {message.get('date', '')}",
                f"Subject: {message.get('subject', '')}",
            ]
            if body:
                message_block.append("Body:\n" + body)

            attachment_names = [att.get("filename", "") for att in message.get("attachments", []) if att.get("filename")]
            if attachment_names:
                message_block.append("Attachments:\n" + "\n".join(f"- {name}" for name in attachment_names[:20]))

            thread_blocks.append("\n".join(message_block))

        block = _to_ascii_safe("\n\n".join(thread_blocks))
        if total_chars + len(block) > max_total_chars and blocks:
            break
        blocks.append(block)
        total_chars += len(block) + 2

    header = (
        f"USER: {user_id}\n"
        f"TOTAL SUMMARIES INCLUDED: {len(summaries)}\n"
        f"TOTAL EMAIL RECORDS INCLUDED: {len(emails)}\n"
        "These are saved historical summaries and linked source emails for this user. "
        "Answer only from this context.\n"
    )
    return _to_ascii_safe(header + "\n\n".join(blocks))


def render_summary_email_html(summary: Dict[str, Any]) -> str:
    sections = [
        ("Executive Summary", summary.get("executive_summary", "")),
        ("Main Topics", summary.get("main_topics", "")),
        ("New Developments", summary.get("new_developments", "")),
        ("Action Items / Asks", summary.get("action_items", "")),
        ("Deadlines / Dates / Meetings", summary.get("deadlines", "")),
        ("Attachment Summary", summary.get("attachment_summary", "")),
        ("Bottom Line", summary.get("bottom_line", "")),
    ]

    def render_block(text: str) -> str:
        lines = [line.strip() for line in str(text).splitlines() if line.strip()]
        if not lines:
            return ""
        bullet_lines = [line[2:] for line in lines if line.startswith("- ")]
        plain_lines = [line for line in lines if not line.startswith("- ")]
        html_parts: List[str] = []
        for line in plain_lines:
            html_parts.append(f"<p style='margin:0 0 10px 0; line-height:1.55;'>{line}</p>")
        if bullet_lines:
            html_parts.append(
                "<ul style='margin:0; padding-left:22px;'>"
                + "".join(f"<li style='margin:0 0 6px 0; line-height:1.5;'>{item}</li>" for item in bullet_lines)
                + "</ul>"
            )
        return "".join(html_parts)

    section_html = []
    for title, content in sections:
        block = render_block(content)
        if not block:
            continue
        section_html.append(
            f"<section style='margin:0 0 18px 0;'>"
            f"<h3 style='margin:0 0 8px 0; font-size:16px; color:#111;'>{title}</h3>"
            f"<div style='background:#fafafa; border:1px solid #e3e3e8; border-radius:14px; padding:14px;'>{block}</div>"
            f"</section>"
        )

    return (
        "<html><body style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; color:#111; "
        "max-width:760px; margin:0 auto; padding:24px; background:#fff;'>"
        f"<h1 style='margin:0 0 6px 0; font-size:28px;'>{summary.get('title', summary.get('summary_id', 'Summary'))}</h1>"
        f"<p style='margin:0 0 24px 0; color:#666;'>Updated: {summary.get('updated_at', '')}</p>"
        + "".join(section_html)
        + "</body></html>"
    )


def send_summary_via_smtp(user_id: str, summary: Dict[str, Any]) -> Dict[str, str]:
    settings = get_settings_for_user(user_id)
    profile = load_profile(user_id) or {}
    smtp_host = settings.get("SMTP_HOST", "")
    smtp_port = int(settings.get("SMTP_PORT", "465") or 465)
    smtp_user = settings.get("SMTP_USER", "")
    smtp_password = settings.get("SMTP_PASSWORD", "")
    recipient = settings.get("SUMMARY_RECIPIENT") or settings.get("IMAP_USER") or profile.get("email", "")

    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        raise HTTPException(status_code=400, detail="Email sending is not configured for this account yet.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = summary.get("title", f"Summary: {summary.get('summary_id', '')}")
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg.attach(MIMEText(render_summary_email_html(summary), "html", "utf-8"))

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, [recipient], msg.as_string())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to send summary email: {exc}") from exc

    return {"recipient": recipient, "subject": msg["Subject"]}


def clean_summary_title(title: str, fallback: str = "Summary") -> str:
    raw_title = str(title or "").strip() or fallback
    return re.sub(r"^Email Summary\s+[—-]\s*", "", raw_title, flags=re.IGNORECASE).strip()


def build_combined_report_markdown(summaries: List[Dict[str, Any]]) -> str:
    blocks: List[str] = []

    for summary in summaries:
        title = clean_summary_title(summary.get("title", ""), summary.get("summary_id", "Summary"))
        parts = [f"## {title}"]

        if summary.get("updated_at"):
            parts.append(f"Updated: {summary.get('updated_at')}")

        primary_text = ""
        for key in [
            "executive_summary",
            "bottom_line",
            "new_developments",
            "action_items",
            "main_topics",
            "deadlines",
        ]:
            content = str(summary.get(key, "") or "").strip()
            if content:
                primary_text = content
                break

        if primary_text:
            parts.append(primary_text)

        blocks.append("\n\n".join(parts))

    return "\n\n".join(blocks)


def generate_combined_summary_content(user_id: str, summary_ids: List[str], request: Request) -> Dict[str, Any]:
    cleaned_summary_ids = [summary_id.strip() for summary_id in summary_ids if summary_id.strip()]
    if not cleaned_summary_ids:
        raise HTTPException(status_code=400, detail="Select at least one summary first.")

    summaries: List[Dict[str, Any]] = []
    for summary_id in cleaned_summary_ids:
        try:
            summaries.append(get_summary(summary_id, request, user_id))
        except HTTPException:
            continue

    if not summaries:
        raise HTTPException(status_code=404, detail="None of the selected summaries could be loaded.")
    combined_markdown = build_combined_report_markdown(summaries)
    return {
        "user_id": user_id,
        "summary_ids": [summary.get("summary_id", "") for summary in summaries],
        "count": len(summaries),
        "combined_markdown": combined_markdown,
        "title": f"Combined Report ({len(summaries)} Selected)",
    }


def parse_markdown_sections(markdown: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current_title = ""
    current_lines: List[str] = []

    def flush() -> None:
        nonlocal current_title, current_lines
        if current_title:
            sections[current_title] = "\n".join(current_lines).strip()
        current_lines = []

    for line in str(markdown or "").splitlines():
        if line.startswith("## "):
            flush()
            current_title = line[3:].strip()
            continue
        if line.startswith("# "):
            continue
        current_lines.append(line)
    flush()
    return sections


def render_markdown_report_email_html(title: str, markdown: str) -> str:
    sections = parse_markdown_sections(markdown)

    def render_block(text: str) -> str:
        lines = [line.strip() for line in str(text).splitlines() if line.strip()]
        if not lines:
            return ""
        bullet_lines = [line[2:] for line in lines if line.startswith("- ")]
        plain_lines = [line for line in lines if not line.startswith("- ")]
        html_parts: List[str] = []
        for line in plain_lines:
            html_parts.append(f"<p style='margin:0 0 10px 0; line-height:1.55;'>{line}</p>")
        if bullet_lines:
            html_parts.append(
                "<ul style='margin:0; padding-left:22px;'>"
                + "".join(f"<li style='margin:0 0 6px 0; line-height:1.5;'>{item}</li>" for item in bullet_lines)
                + "</ul>"
            )
        return "".join(html_parts)

    ordered_titles = [
        "Executive Summary",
        "Main Themes",
        "Key Action Items",
        "Deadlines / Dates",
        "Notable Attachments",
        "Bottom Line",
    ]

    section_html: List[str] = []
    for section_title in ordered_titles:
        block = render_block(sections.get(section_title, ""))
        if not block:
            continue
        section_html.append(
            f"<section style='margin:0 0 18px 0;'>"
            f"<h3 style='margin:0 0 8px 0; font-size:16px; color:#111;'>{section_title}</h3>"
            f"<div style='background:#fafafa; border:1px solid #e3e3e8; border-radius:14px; padding:14px;'>{block}</div>"
            f"</section>"
        )

    if not section_html and sections:
        for section_title, section_content in sections.items():
            block = render_block(section_content)
            if not block:
                continue
            section_html.append(
                f"<section style='margin:0 0 18px 0;'>"
                f"<h3 style='margin:0 0 8px 0; font-size:16px; color:#111;'>{section_title}</h3>"
                f"<div style='background:#fafafa; border:1px solid #e3e3e8; border-radius:14px; padding:14px;'>{block}</div>"
                f"</section>"
            )

    if not section_html:
        section_html.append(
            f"<section style='margin:0 0 18px 0;'>"
            f"<div style='background:#fafafa; border:1px solid #e3e3e8; border-radius:14px; padding:14px;'>"
            f"{render_block(markdown)}"
            f"</div></section>"
        )

    return (
        "<html><body style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; color:#111; "
        "max-width:760px; margin:0 auto; padding:24px; background:#fff;'>"
        f"<h1 style='margin:0 0 24px 0; font-size:28px;'>{title}</h1>"
        + "".join(section_html)
        + "</body></html>"
    )


def send_combined_report_via_smtp(user_id: str, title: str, markdown: str) -> Dict[str, str]:
    settings = get_settings_for_user(user_id)
    profile = load_profile(user_id) or {}
    smtp_host = settings.get("SMTP_HOST", "")
    smtp_port = int(settings.get("SMTP_PORT", "465") or 465)
    smtp_user = settings.get("SMTP_USER", "")
    smtp_password = settings.get("SMTP_PASSWORD", "")
    recipient = settings.get("SUMMARY_RECIPIENT") or settings.get("IMAP_USER") or profile.get("email", "")

    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        raise HTTPException(status_code=400, detail="Email sending is not configured for this account yet.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = title
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg.attach(MIMEText(render_markdown_report_email_html(title, markdown), "html", "utf-8"))

    try:
        if smtp_port == 587:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [recipient], msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [recipient], msg.as_string())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to send combined report email: {exc}") from exc

    return {"recipient": recipient, "subject": msg["Subject"]}


@app.post("/chat")
def chat(payload: ChatRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    question = payload.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    summaries = get_chat_ready_summaries(resolved_user_id)
    if not summaries:
        raise HTTPException(status_code=404, detail=f"No saved summaries found for user '{resolved_user_id}'.")
    emails = get_chat_ready_emails(resolved_user_id, summaries)
    attachment_matches = find_attachment_matches(resolved_user_id, emails, payload.question)
    attachment_intent = bool(re.search(r"\b(show|open|display|pull up|bring up|view|download)\b", question, flags=re.IGNORECASE))

    if attachment_matches and attachment_intent:
        return {
            "user_id": resolved_user_id,
            "answer": "I found matching attachment files below. You can open them directly.",
            "summary_count": len(summaries),
            "email_count": len(emails),
            "attachment_matches": attachment_matches,
        }

    settings = get_settings_for_user(resolved_user_id)
    api_key = settings.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    model = settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o"
    if not api_key:
        raise HTTPException(status_code=500, detail=f"No OPENAI_API_KEY configured for user '{resolved_user_id}'.")

    client = OpenAI(api_key=api_key)
    context = build_chat_context(resolved_user_id, summaries, emails)
    instructions = (
        "You are a grounded assistant answering questions about one user's historical email summaries and source emails. "
        "Address the user as 'you' rather than by name. "
        "Answer only from the provided context. Do not invent facts, deadlines, requests, attachments, or email text. "
        "If the answer is not in the provided summaries or email bodies, say so clearly. "
        "If the user asks where something was said, quote the exact relevant email text when available. "
        "If the user asks about attachments, mention attachment filenames explicitly when available. "
        "Prefer practical, concise answers."
    )
    input_text = (
        "CONTEXT\n"
        f"{context}\n\n"
        "QUESTION\n"
        f"{_to_ascii_safe(question)}\n"
    )

    try:
        response = client.responses.create(
            model=model,
            instructions=instructions,
            input=input_text,
            temperature=0.1,
            max_output_tokens=700,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"OpenAI chat request failed: {exc}") from exc

    return {
        "user_id": resolved_user_id,
        "answer": response.output_text,
        "summary_count": len(summaries),
        "email_count": len(emails),
        "attachment_matches": attachment_matches,
    }


@app.post("/summaries/combined")
def combined_summary(payload: CombinedSummaryRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    return generate_combined_summary_content(resolved_user_id, payload.summary_ids, request)


@app.post("/summaries/combined/send-email")
def send_combined_summary_email(payload: CombinedSummaryRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    combined = generate_combined_summary_content(resolved_user_id, payload.summary_ids, request)
    delivery = send_combined_report_via_smtp(
        resolved_user_id,
        combined["title"],
        combined["combined_markdown"],
    )
    return {
        "success": True,
        "user_id": resolved_user_id,
        "summary_ids": combined["summary_ids"],
        "count": combined["count"],
        **delivery,
    }


@app.post("/summaries/refine")
def refine_summary(payload: RefineSummaryRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    markdown = str(payload.markdown or "").strip()
    instructions = str(payload.instructions or "").strip()
    title = str(payload.title or "Refined Summary").strip()

    if not markdown:
        raise HTTPException(status_code=400, detail="No summary content was provided.")
    if not instructions:
        raise HTTPException(status_code=400, detail="Refinement instructions cannot be empty.")

    settings = get_settings_for_user(resolved_user_id)
    api_key = settings.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    model = settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o"
    saved_preferences = parse_summary_style_preferences(settings)
    if not api_key:
        raise HTTPException(status_code=500, detail=f"No OPENAI_API_KEY configured for user '{resolved_user_id}'.")

    client = OpenAI(api_key=api_key)
    instructions_text = (
        "You are refining an existing email summary for one user. "
        "Keep the output grounded in the provided summary content only. "
        "Do not add new facts, deadlines, people, or attachments. "
        "Follow the user's refinement request closely. "
        + (
            "The user also has saved summary style preferences. Apply them unless the current refinement request conflicts:\n"
            + "\n".join(f"- {item}" for item in saved_preferences)
            + "\n"
            if saved_preferences else ""
        )
        + (
        "Return Markdown. Keep the result well structured and easy to scan. "
        "Use section headers where helpful."
        )
    )
    input_text = (
        f"CURRENT TITLE\n{_to_ascii_safe(title)}\n\n"
        f"CURRENT SUMMARY\n{_to_ascii_safe(markdown)}\n\n"
        f"REFINEMENT REQUEST\n{_to_ascii_safe(instructions)}\n"
    )

    try:
        response = client.responses.create(
            model=model,
            instructions=instructions_text,
            input=input_text,
            temperature=0.2,
            max_output_tokens=1800,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Refine summary request failed: {exc}") from exc

    updated_preferences = saved_preferences
    if payload.save_preference:
        updated_preferences = add_summary_style_preference(resolved_user_id, instructions)

    return {
        "user_id": resolved_user_id,
        "title": title,
        "refined_markdown": response.output_text,
        "summary_style_preferences": updated_preferences,
    }


@app.post("/summary-style-preferences")
def create_summary_style_preference(payload: SummaryStylePreferenceRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    preference = payload.preference.strip()
    if not preference:
        raise HTTPException(status_code=400, detail="Preference cannot be empty.")
    preferences = add_summary_style_preference(resolved_user_id, preference)
    return {"success": True, "user_id": resolved_user_id, "summary_style_preferences": preferences}


@app.post("/summary-style-preferences/remove")
def delete_summary_style_preference(payload: SummaryStylePreferenceRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    preference = payload.preference.strip()
    if not preference:
        raise HTTPException(status_code=400, detail="Preference cannot be empty.")
    preferences = remove_summary_style_preference(resolved_user_id, preference)
    return {"success": True, "user_id": resolved_user_id, "summary_style_preferences": preferences}


@app.post("/run-summarizer")
def run_summarizer(payload: RunSummarizerRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    env = os.environ.copy()
    env["CLIENT_NAME"] = resolved_user_id
    env["PROFILE_USER_ID"] = resolved_user_id
    env["DAYS_BACK"] = str(payload.days_back)

    result = subprocess.run(
        ["python3", "email_v13.py"],
        cwd=str(BASE_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )

    response = {
        "user_id": resolved_user_id,
        "days_back": payload.days_back,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "success": result.returncode == 0,
    }
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=response)

    parsed_stats = {}
    for line in reversed(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "stats" in payload:
            parsed_stats = payload.get("stats") or {}
            break

    response["stats"] = parsed_stats
    return response


@app.get("/summaries")
def list_summaries(request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    contact_profiles = parse_contact_profiles(get_settings_for_user(user_id))
    json_summaries_dir = get_user_json_summaries_dir(user_id)
    summaries_dir = get_user_summaries_dir(user_id)
    if json_summaries_dir.exists():
        summary_files = sorted(json_summaries_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        summaries = [
            apply_contact_profile_to_summary(load_summary_json_preview(path), contact_profiles)
            for path in summary_files
            if not path.stem.startswith("overall_master_")
        ]
        return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "json"}

    if not summaries_dir.exists():
        return {"user_id": user_id, "summaries": [], "message": "No current summaries."}

    summary_files = sorted(summaries_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    summaries = [load_summary_file(path) for path in summary_files]

    for summary in summaries:
        summary.pop("content_markdown", None)

    return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "markdown"}


@app.get("/summaries/{summary_id}")
def get_summary(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    contact_profiles = parse_contact_profiles(get_settings_for_user(user_id))
    json_summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if json_summary_path.exists():
        return apply_contact_profile_to_summary(load_summary_json(json_summary_path), contact_profiles)

    summary_path = get_user_summaries_dir(user_id) / f"{summary_id}.md"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    return load_summary_file(summary_path)


@app.post("/summaries/{summary_id}/send-email")
def send_summary_email(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    summary = get_summary(summary_id, request, user_id)
    delivery = send_summary_via_smtp(user_id, summary)
    return {
        "success": True,
        "user_id": user_id,
        "summary_id": summary_id,
        **delivery,
    }
