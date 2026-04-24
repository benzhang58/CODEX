import json
import os
import re
import shutil
import hashlib
import hmac
import imaplib
import secrets
import smtplib
import sqlite3
import subprocess
import threading
import unicodedata
import base64
from functools import lru_cache
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from dotenv import dotenv_values
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, ListFlowable, ListItem

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
RUN_JOB_LOCK = threading.Lock()
RUN_JOBS: Dict[str, Dict[str, Any]] = {}
SCHEDULE_RUNNER_LOCK = threading.Lock()
ACTIVE_SCHEDULE_RUNS: set[str] = set()

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
PUBLIC_REPORTS_DIR = APP_STORAGE_DIR / "public_reports"
SESSION_COOKIE_NAME = "email_dashboard_session"
SESSION_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7
READ_RETENTION_DAYS = 20
GOOGLE_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
GOOGLE_OAUTH_STATE_COOKIE = "email_dashboard_google_state"
GOOGLE_OAUTH_NEXT_COOKIE = "email_dashboard_google_next"
GOOGLE_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]
REQUIRED_GOOGLE_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
REQUIRED_GOOGLE_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
TERMS_VERSION = "2026-04-23"
PRIVACY_VERSION = "2026-04-23"
MICROSOFT_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
MICROSOFT_OAUTH_STATE_COOKIE = "email_dashboard_microsoft_state"
MICROSOFT_OAUTH_NEXT_COOKIE = "email_dashboard_microsoft_next"
MICROSOFT_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "offline_access",
    "User.Read",
    "https://outlook.office.com/IMAP.AccessAsUser.All",
]

app.mount("/dashboard_static", StaticFiles(directory=STATIC_DIR), name="dashboard_static")


def get_db_connection() -> sqlite3.Connection:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def track_analytics_event(user_id: str, event_name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO analytics_events (event_id, user_id, event_name, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                secrets.token_hex(12),
                user_id,
                event_name,
                datetime.now().isoformat(),
                json.dumps(metadata or {}, ensure_ascii=False),
            ),
        )


def analytics_event_exists(user_id: str, event_name: str) -> bool:
    with get_db_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM analytics_events WHERE user_id = ? AND event_name = ? LIMIT 1",
            (user_id, event_name),
        ).fetchone()
    return bool(row)


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

            CREATE TABLE IF NOT EXISTS report_schedules (
                schedule_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                interval_value INTEGER NOT NULL,
                interval_unit TEXT NOT NULL,
                days_back INTEGER NOT NULL DEFAULT 7,
                recipient_email TEXT NOT NULL,
                run_summarizer_first INTEGER NOT NULL DEFAULT 1,
                send_combined_report INTEGER NOT NULL DEFAULT 1,
                preferred_hour INTEGER NOT NULL DEFAULT 8,
                preferred_minute INTEGER NOT NULL DEFAULT 0,
                timezone TEXT NOT NULL DEFAULT 'America/Los_Angeles',
                delivery_channel TEXT NOT NULL DEFAULT 'email',
                recipient_phone TEXT,
                last_run_at TEXT,
                next_run_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS analytics_events (
                event_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                event_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS bug_reports (
                bug_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                page_url TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        existing_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "microsoft_oauth_json" not in existing_columns:
            connection.execute("ALTER TABLE users ADD COLUMN microsoft_oauth_json TEXT")

        existing_schedule_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(report_schedules)").fetchall()
        }
        if existing_schedule_columns:
            if "delivery_channel" not in existing_schedule_columns:
                connection.execute("ALTER TABLE report_schedules ADD COLUMN delivery_channel TEXT NOT NULL DEFAULT 'email'")
            if "recipient_phone" not in existing_schedule_columns:
                connection.execute("ALTER TABLE report_schedules ADD COLUMN recipient_phone TEXT")

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


class SummaryDoneRequest(BaseModel):
    user_id: Optional[str] = None
    done: bool = True


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


class BugReportRequest(BaseModel):
    user_id: Optional[str] = None
    title: str
    description: str
    page_url: str = ""
    user_agent: str = ""
    metadata: Optional[Dict[str, Any]] = None


class SignupRequest(BaseModel):
    user_id: Optional[str] = None
    email: str
    password: str
    birthday: str = ""
    gender: str = ""
    accept_terms: bool = False
    accept_privacy: bool = False


class LoginRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None
    password: str


class ProfileUpdateRequest(BaseModel):
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    attachment_ai_enabled: Optional[bool] = None
    openai_api_key: str = ""
    openai_model: str = "gpt-5.1"
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


class ReportScheduleRequest(BaseModel):
    user_id: Optional[str] = None
    name: str = "Scheduled Report"
    active: bool = True
    interval_value: int = 1
    interval_unit: str = "days"
    days_back: int = 7
    recipient_email: str = ""
    run_summarizer_first: bool = True
    send_combined_report: bool = True
    preferred_hour: int = 8
    preferred_minute: int = 0
    timezone: str = "America/Los_Angeles"
    delivery_channel: str = "email"
    recipient_phone: str = ""


class ReportScheduleRunRequest(BaseModel):
    user_id: Optional[str] = None
    ran_at: Optional[str] = None


class CombinedSummaryTextRequest(BaseModel):
    user_id: Optional[str] = None
    summary_ids: List[str]
    phone_number: str = ""


class LegalAcceptanceRequest(BaseModel):
    user_id: Optional[str] = None
    accept_terms: bool = True
    accept_privacy: bool = True


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "home.html")


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
def login_page(request: Request) -> Response:
    if get_session_user_id(request):
        return RedirectResponse("/dashboard")
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


@app.get("/privacy")
def privacy_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "privacy.html")


@app.get("/terms")
def terms_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "terms.html")


@app.post("/auth/signup")
def signup(request: SignupRequest, response: Response) -> Dict[str, Any]:
    email = request.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required.")
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Incorrect email.")
    user_id = _slugify_user_id(request.user_id) if request.user_id and request.user_id.strip() else user_id_from_email(email)
    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if not request.accept_terms or not request.accept_privacy:
        raise HTTPException(status_code=400, detail="You must accept the Terms of Service and Privacy Policy.")
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
    settings["MAILBOX_CONNECTION_CONFIRMED"] = "true"
    settings["BIRTHDAY"] = str(request.birthday or "").strip()
    settings["GENDER"] = str(request.gender or "").strip()
    mark_legal_acceptance(settings)

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
    track_analytics_event(user_id, "signup_conversion", {"auth_provider": "password"})
    create_session(response, user_id)
    return {"success": True, "profile": profile_response(profile)}


@app.post("/auth/login")
def login(request: LoginRequest, response: Response) -> Dict[str, Any]:
    profile = None
    if request.email and request.email.strip():
        if not is_valid_email(request.email):
            raise HTTPException(status_code=400, detail="Incorrect email.")
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


@app.delete("/auth/account")
def delete_account(request: Request, response: Response) -> Dict[str, Any]:
    user_id = resolve_user_id(request)
    profile = load_profile_or_404(user_id)

    with get_db_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    user_data_dir = DATA_DIR / user_id
    user_output_dir = OUTPUT_ROOT_DIR / user_id
    if user_data_dir.exists():
        shutil.rmtree(user_data_dir, ignore_errors=True)
    if user_output_dir.exists():
        shutil.rmtree(user_output_dir, ignore_errors=True)

    clear_session(response, request)
    return {"success": True, "user_id": profile["user_id"], "email": profile.get("email", "")}


@app.get("/auth/google/start")
def auth_google_start(
    next: str = "/dashboard",
    login_hint: str = "",
    prompt: str = "",
) -> RedirectResponse:
    try:
        config = get_google_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?google_error=not_configured")
    state = secrets.token_urlsafe(24)
    GOOGLE_OAUTH_STATE[state] = {"next": next}
    scope = " ".join(GOOGLE_OAUTH_SCOPES)
    login_hint_value = login_hint.strip()
    prompt_value = prompt.strip()
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={quote(config['client_id'], safe='')}"
        f"&redirect_uri={quote(config['redirect_uri'], safe='')}"
        "&response_type=code"
        f"&scope={quote(scope, safe='')}"
        "&access_type=offline"
        f"&state={quote(state, safe='')}"
    )
    if login_hint_value:
        auth_url += f"&login_hint={quote(login_hint_value, safe='')}"
    if prompt_value:
        auth_url += f"&prompt={quote(prompt_value, safe='')}"
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
    known_state = GOOGLE_OAUTH_STATE.get(state or "")
    if not code or not state:
        return RedirectResponse("/dashboard?google_error=invalid_callback")
    if cookie_state and state == cookie_state:
        pass
    elif known_state:
        pass
    else:
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
    display_name = str(userinfo.get("name") or userinfo.get("given_name") or "").strip()
    if not email:
        response = RedirectResponse("/dashboard?google_error=no_email_returned")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    profile = find_profile_by_email(email)
    created_new_profile = False
    if not profile:
        created_new_profile = True
        user_id = user_id_from_email(email)
        settings = default_profile_settings()
        settings["IMAP_USER"] = email
        settings["SMTP_USER"] = email
        settings["SUMMARY_RECIPIENT"] = email
        settings["MAILBOX_CONNECTION_CONFIRMED"] = "true"
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
    profile["settings"] = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    profile["settings"] = apply_profile_name_defaults(profile["settings"], display_name)
    profile["settings"]["IMAP_USER"] = profile["settings"].get("IMAP_USER") or email
    profile["settings"]["SMTP_USER"] = profile["settings"].get("SMTP_USER") or email
    profile["settings"]["SUMMARY_RECIPIENT"] = profile["settings"].get("SUMMARY_RECIPIENT") or email
    profile["settings"]["MAILBOX_CONNECTION_CONFIRMED"] = "true"
    save_profile(profile)
    if created_new_profile:
        track_analytics_event(profile["user_id"], "signup_conversion", {"auth_provider": "google"})

    response = RedirectResponse(next_url)
    create_session(response, profile["user_id"])
    response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    return response


@app.get("/auth/microsoft/start")
def auth_microsoft_start(
    next: str = "/dashboard",
    login_hint: str = "",
    prompt: str = "",
) -> RedirectResponse:
    try:
        config = get_microsoft_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?microsoft_error=not_configured")

    state = secrets.token_urlsafe(24)
    MICROSOFT_OAUTH_STATE[state] = {"next": next}
    scope = " ".join(MICROSOFT_OAUTH_SCOPES)
    login_hint_value = login_hint.strip()
    prompt_value = prompt.strip()
    auth_url = (
        f"https://login.microsoftonline.com/{quote(config['tenant'], safe='')}/oauth2/v2.0/authorize"
        f"?client_id={quote(config['client_id'], safe='')}"
        "&response_type=code"
        f"&redirect_uri={quote(config['redirect_uri'], safe='')}"
        "&response_mode=query"
        f"&scope={quote(scope, safe='')}"
        f"&state={quote(state, safe='')}"
    )
    if login_hint_value:
        auth_url += f"&login_hint={quote(login_hint_value, safe='')}"
    if prompt_value:
        auth_url += f"&prompt={quote(prompt_value, safe='')}"
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
    known_state = MICROSOFT_OAUTH_STATE.get(state or "")
    if not code or not state:
        return RedirectResponse("/dashboard?microsoft_error=invalid_callback")
    if cookie_state and state == cookie_state:
        pass
    elif known_state:
        pass
    else:
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

    fallback_email = str(userinfo.get("mail") or userinfo.get("userPrincipalName") or "").strip().lower()
    display_name = str(userinfo.get("displayName", "") or "").strip()
    email = resolve_microsoft_account_email(userinfo, token_payload) or fallback_email
    if not email:
        response = RedirectResponse("/dashboard?microsoft_error=no_email_returned")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    profile = find_profile_by_email(email)
    created_new_profile = False
    if not profile and fallback_email and fallback_email != email:
        profile = find_profile_by_email(fallback_email)
    if not profile:
        created_new_profile = True
        user_id = user_id_from_email(email)
        settings = default_profile_settings()
        settings = apply_provider_defaults(settings, email, force_outlook=True)
        settings["IMAP_USER"] = email
        settings["SMTP_USER"] = email
        settings["SUMMARY_RECIPIENT"] = email
        settings["MAILBOX_CONNECTION_CONFIRMED"] = "true"
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
    else:
        profile["email"] = email

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
    profile["settings"] = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    profile["settings"] = apply_profile_name_defaults(profile["settings"], display_name)
    profile["settings"] = apply_provider_defaults(profile["settings"], email, force_outlook=True)
    profile["settings"]["IMAP_USER"] = profile["settings"].get("IMAP_USER") or email
    profile["settings"]["SMTP_USER"] = profile["settings"].get("SMTP_USER") or email
    profile["settings"]["SUMMARY_RECIPIENT"] = profile["settings"].get("SUMMARY_RECIPIENT") or email
    profile["settings"]["MAILBOX_CONNECTION_CONFIRMED"] = "true"
    save_profile(profile)
    if created_new_profile:
        track_analytics_event(profile["user_id"], "signup_conversion", {"auth_provider": "microsoft"})

    response = RedirectResponse(next_url)
    create_session(response, profile["user_id"])
    response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
    return response


@app.get("/auth/me")
def auth_me(request: Request, response: Response) -> Dict[str, Any]:
    user_id = get_session_user_id(request)
    if not user_id:
        return {"authenticated": False}

    profile = load_profile(user_id)
    if not profile:
        return {"authenticated": False}

    refresh_session_cookie(response, request)
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


@app.post("/profile/how-to-seen")
def mark_how_to_seen(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = mark_profile_how_to_seen(resolved_user_id)
    return {"success": True, "profile": profile_response(profile)}


@app.post("/profile/legal-acceptance")
def accept_legal_terms(
    request: Request,
    payload: LegalAcceptanceRequest,
) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    if not payload.accept_terms or not payload.accept_privacy:
        raise HTTPException(status_code=400, detail="Both the Terms of Service and Privacy Policy must be accepted.")
    profile = load_profile_or_404(resolved_user_id)
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    profile["settings"] = mark_legal_acceptance(settings)
    save_profile(profile)
    return {"success": True, "profile": profile_response(profile)}


@app.get("/report-schedules")
def list_report_schedules(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    with get_db_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM report_schedules WHERE user_id = ? ORDER BY lower(name), created_at",
            (resolved_user_id,),
        ).fetchall()
    return {
        "user_id": resolved_user_id,
        "count": len(rows),
        "schedules": [row_to_report_schedule(row) for row in rows],
    }


@app.post("/report-schedules")
def create_report_schedule(payload: ReportScheduleRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    profile = load_profile_or_404(resolved_user_id)
    normalized = normalize_schedule_payload(
        payload,
        fallback_recipient=(profile.get("settings") or {}).get("SUMMARY_RECIPIENT") or profile.get("email", ""),
    )
    now_iso = datetime.now().isoformat()
    schedule_id = secrets.token_hex(12)
    next_run_at = compute_next_schedule_run(
        timezone_name=normalized["timezone"],
        interval_value=normalized["interval_value"],
        interval_unit=normalized["interval_unit"],
        preferred_hour=normalized["preferred_hour"],
        preferred_minute=normalized["preferred_minute"],
    )
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO report_schedules (
                schedule_id, user_id, name, active, interval_value, interval_unit, days_back,
                recipient_email, run_summarizer_first, send_combined_report,
                preferred_hour, preferred_minute, timezone, delivery_channel, recipient_phone,
                last_run_at, next_run_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                schedule_id,
                resolved_user_id,
                normalized["name"],
                1 if normalized["active"] else 0,
                normalized["interval_value"],
                normalized["interval_unit"],
                normalized["days_back"],
                normalized["recipient_email"],
                1 if normalized["run_summarizer_first"] else 0,
                1 if normalized["send_combined_report"] else 0,
                normalized["preferred_hour"],
                normalized["preferred_minute"],
                normalized["timezone"],
                normalized["delivery_channel"],
                normalized["recipient_phone"],
                None,
                next_run_at,
                now_iso,
                now_iso,
            ),
        )
        row = connection.execute(
            "SELECT * FROM report_schedules WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()
    track_analytics_event(
        resolved_user_id,
        "scheduled_report_created",
        {
            "schedule_id": schedule_id,
            "delivery_channel": normalized["delivery_channel"],
            "interval_unit": normalized["interval_unit"],
            "interval_value": normalized["interval_value"],
        },
    )
    return {"success": True, "schedule": row_to_report_schedule(row)}


@app.put("/report-schedules/{schedule_id}")
def update_report_schedule(
    schedule_id: str,
    payload: ReportScheduleRequest,
    request: Request,
) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    profile = load_profile_or_404(resolved_user_id)
    normalized = normalize_schedule_payload(
        payload,
        fallback_recipient=(profile.get("settings") or {}).get("SUMMARY_RECIPIENT") or profile.get("email", ""),
    )
    with get_db_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Scheduled report not found.")

        next_run_at = compute_next_schedule_run(
            timezone_name=normalized["timezone"],
            interval_value=normalized["interval_value"],
            interval_unit=normalized["interval_unit"],
            preferred_hour=normalized["preferred_hour"],
            preferred_minute=normalized["preferred_minute"],
            last_run_at=existing["last_run_at"],
        )
        connection.execute(
            """
            UPDATE report_schedules
            SET name = ?, active = ?, interval_value = ?, interval_unit = ?, days_back = ?,
                recipient_email = ?, run_summarizer_first = ?, send_combined_report = ?,
                preferred_hour = ?, preferred_minute = ?, timezone = ?, delivery_channel = ?, recipient_phone = ?,
                next_run_at = ?, updated_at = ?
            WHERE schedule_id = ? AND user_id = ?
            """,
            (
                normalized["name"],
                1 if normalized["active"] else 0,
                normalized["interval_value"],
                normalized["interval_unit"],
                normalized["days_back"],
                normalized["recipient_email"],
                1 if normalized["run_summarizer_first"] else 0,
                1 if normalized["send_combined_report"] else 0,
                normalized["preferred_hour"],
                normalized["preferred_minute"],
                normalized["timezone"],
                normalized["delivery_channel"],
                normalized["recipient_phone"],
                next_run_at,
                datetime.now().isoformat(),
                schedule_id,
                resolved_user_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        ).fetchone()
    return {"success": True, "schedule": row_to_report_schedule(row)}


@app.delete("/report-schedules/{schedule_id}")
def delete_report_schedule(schedule_id: str, request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    with get_db_connection() as connection:
        existing = connection.execute(
            "SELECT schedule_id FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Scheduled report not found.")
        connection.execute(
            "DELETE FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        )
    return {"success": True, "schedule_id": schedule_id}


@app.post("/report-schedules/{schedule_id}/mark-ran")
def mark_report_schedule_ran(
    schedule_id: str,
    payload: ReportScheduleRunRequest,
    request: Request,
) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    with get_db_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Scheduled report not found.")

        ran_at_dt = parse_iso_datetime(payload.ran_at, existing["timezone"]) or datetime.now(ZoneInfo(existing["timezone"]))
        next_run_at = compute_next_schedule_run(
            now=ran_at_dt,
            timezone_name=existing["timezone"],
            interval_value=int(existing["interval_value"]),
            interval_unit=str(existing["interval_unit"]),
            preferred_hour=int(existing["preferred_hour"]),
            preferred_minute=int(existing["preferred_minute"]),
            last_run_at=ran_at_dt.isoformat(),
        )
        connection.execute(
            """
            UPDATE report_schedules
            SET last_run_at = ?, next_run_at = ?, updated_at = ?
            WHERE schedule_id = ? AND user_id = ?
            """,
            (
                ran_at_dt.isoformat(),
                next_run_at,
                datetime.now().isoformat(),
                schedule_id,
                resolved_user_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM report_schedules WHERE schedule_id = ? AND user_id = ?",
            (schedule_id, resolved_user_id),
        ).fetchone()
    return {"success": True, "schedule": row_to_report_schedule(row)}


@app.get("/mailbox/status")
def get_mailbox_status(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    microsoft_connected = bool((profile.get("microsoft_oauth") or {}).get("refresh_token") or (profile.get("microsoft_oauth") or {}).get("access_token"))
    if google_connected or microsoft_connected:
        return {
            "connected": True,
            "status": "Connected",
            "reason": "oauth_connected",
        }

    settings = apply_provider_defaults(
        merge_stored_settings(default_profile_settings(), profile.get("settings") or {}),
        profile.get("email", ""),
    )
    email = str(settings.get("IMAP_USER", "")).strip()
    password = str(settings.get("IMAP_PASSWORD", "")).strip()
    server = str(settings.get("IMAP_SERVER", "")).strip()
    port = int(str(settings.get("IMAP_PORT", "993")).strip() or "993")

    if not all([email, password, server]):
        return {
            "connected": False,
            "status": "Not Connected",
            "reason": "missing_credentials",
        }

    try:
        mail = imaplib.IMAP4_SSL(server, port)
        try:
            mail.login(email, password)
            mail.logout()
        except Exception:
            try:
                mail.shutdown()
            except Exception:
                pass
            raise
    except Exception:
        return {
            "connected": False,
            "status": "Not Connected",
            "reason": "login_failed",
        }

    return {
        "connected": True,
        "status": "Connected",
        "reason": "ok",
    }


def _slugify_user_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "", value.strip()) or "user"


def is_valid_email(value: str) -> bool:
    email = value.strip()
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def is_valid_e164_phone(value: str) -> bool:
    phone = str(value or "").strip()
    return bool(re.fullmatch(r"\+[1-9]\d{7,14}", phone))


def normalize_schedule_timezone(value: str) -> str:
    candidate = str(value or "").strip() or "America/Los_Angeles"
    try:
        ZoneInfo(candidate)
        return candidate
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid schedule timezone.")


def normalize_schedule_unit(value: str) -> str:
    unit = str(value or "").strip().lower()
    if unit not in {"hours", "days", "weeks"}:
        raise HTTPException(status_code=400, detail="interval_unit must be one of: hours, days, weeks.")
    return unit


def normalize_schedule_payload(
    payload: ReportScheduleRequest,
    fallback_recipient: str = "",
) -> Dict[str, Any]:
    interval_value = int(payload.interval_value or 0)
    if interval_value < 1:
        raise HTTPException(status_code=400, detail="interval_value must be at least 1.")
    days_back = int(payload.days_back or 0)
    if days_back < 1:
        raise HTTPException(status_code=400, detail="days_back must be at least 1.")
    preferred_hour = int(payload.preferred_hour or 0)
    preferred_minute = int(payload.preferred_minute or 0)
    if preferred_hour < 0 or preferred_hour > 23:
        raise HTTPException(status_code=400, detail="preferred_hour must be between 0 and 23.")
    if preferred_minute < 0 or preferred_minute > 59:
        raise HTTPException(status_code=400, detail="preferred_minute must be between 0 and 59.")

    delivery_channel = str(payload.delivery_channel or "email").strip().lower()
    if delivery_channel not in {"email", "sms"}:
        raise HTTPException(status_code=400, detail="delivery_channel must be either 'email' or 'sms'.")

    recipient_email = str(payload.recipient_email or "").strip() or str(fallback_recipient or "").strip()
    recipient_phone = str(payload.recipient_phone or "").strip()
    if delivery_channel == "email" and not is_valid_email(recipient_email):
        raise HTTPException(status_code=400, detail="A valid recipient_email is required for email delivery.")
    if delivery_channel == "sms" and not is_valid_e164_phone(recipient_phone):
        raise HTTPException(status_code=400, detail="A valid E.164 recipient_phone is required for SMS delivery.")

    return {
        "name": str(payload.name or "").strip() or "Scheduled Report",
        "active": bool(payload.active),
        "interval_value": interval_value,
        "interval_unit": normalize_schedule_unit(payload.interval_unit),
        "days_back": days_back,
        "recipient_email": recipient_email,
        "recipient_phone": recipient_phone,
        "delivery_channel": delivery_channel,
        "run_summarizer_first": bool(payload.run_summarizer_first),
        "send_combined_report": bool(payload.send_combined_report),
        "preferred_hour": preferred_hour,
        "preferred_minute": preferred_minute,
        "timezone": normalize_schedule_timezone(payload.timezone),
    }


def parse_iso_datetime(value: Optional[str], timezone_name: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except Exception:
        return None
    tz = ZoneInfo(timezone_name)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=tz)
    return parsed.astimezone(tz)


def compute_next_schedule_run(
    *,
    now: Optional[datetime] = None,
    timezone_name: str,
    interval_value: int,
    interval_unit: str,
    preferred_hour: int,
    preferred_minute: int,
    last_run_at: Optional[str] = None,
) -> str:
    tz = ZoneInfo(timezone_name)
    reference_now = now.astimezone(tz) if now and now.tzinfo else (now.replace(tzinfo=tz) if now else datetime.now(tz))
    last_run = parse_iso_datetime(last_run_at, timezone_name)

    if interval_unit == "hours":
        anchor = last_run or reference_now
        candidate = anchor + timedelta(hours=interval_value)
        if candidate <= reference_now:
            candidate = reference_now + timedelta(hours=interval_value)
        return candidate.isoformat()

    base_date = (last_run or reference_now).date()
    candidate = datetime(
        year=base_date.year,
        month=base_date.month,
        day=base_date.day,
        hour=preferred_hour,
        minute=preferred_minute,
        tzinfo=tz,
    )
    if last_run:
        delta = timedelta(days=interval_value if interval_unit == "days" else interval_value * 7)
        candidate = candidate + delta
    elif candidate <= reference_now:
        delta = timedelta(days=interval_value if interval_unit == "days" else interval_value * 7)
        candidate = candidate + delta
    return candidate.isoformat()


def row_to_report_schedule(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "schedule_id": row["schedule_id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "active": bool(row["active"]),
        "interval_value": int(row["interval_value"]),
        "interval_unit": row["interval_unit"],
        "days_back": int(row["days_back"]),
        "recipient_email": row["recipient_email"],
        "recipient_phone": row["recipient_phone"] or "",
        "delivery_channel": row["delivery_channel"] or "email",
        "run_summarizer_first": bool(row["run_summarizer_first"]),
        "send_combined_report": bool(row["send_combined_report"]),
        "preferred_hour": int(row["preferred_hour"]),
        "preferred_minute": int(row["preferred_minute"]),
        "timezone": row["timezone"],
        "last_run_at": row["last_run_at"],
        "next_run_at": row["next_run_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


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
        f"{PUBLIC_BASE_URL}/auth/microsoft/callback" if PUBLIC_BASE_URL else "http://localhost:8000/auth/microsoft/callback"
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


def post_json_with_bearer(url: str, access_token: str, payload: Dict[str, Any], error_prefix: str) -> Dict[str, Any]:
    request = UrlRequest(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"{error_prefix}: {body}") from exc


def refresh_google_access_token(profile: Dict[str, Any]) -> str:
    google_oauth = profile.get("google_oauth") or {}
    refresh_token = str(google_oauth.get("refresh_token", "")).strip()
    access_token = str(google_oauth.get("access_token", "")).strip()
    if access_token and not refresh_token:
        return access_token
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail="Google email sending needs a refreshed Google sign-in for this account.",
        )

    config = get_google_oauth_config()
    token_payload = post_form_json(
        "https://oauth2.googleapis.com/token",
        {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        error_prefix="Google token refresh failed",
    )
    new_access_token = str(token_payload.get("access_token", "")).strip()
    if not new_access_token:
        raise HTTPException(status_code=500, detail="Google token refresh did not return an access token.")

    google_oauth["access_token"] = new_access_token
    google_oauth["updated_at"] = datetime.now().isoformat()
    profile["google_oauth"] = google_oauth
    save_profile(profile)
    return new_access_token


def parse_oauth_scope_text(scope_value: Any) -> set[str]:
    return {part.strip() for part in str(scope_value or "").split() if part.strip()}


def google_oauth_has_scope(profile: Dict[str, Any], required_scope: str) -> bool:
    google_oauth = profile.get("google_oauth") or {}
    scopes = parse_oauth_scope_text(google_oauth.get("scope", ""))
    return required_scope in scopes


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    token_text = str(token or "").strip()
    if not token_text or token_text.count(".") < 2:
        return {}
    try:
        payload_segment = token_text.split(".")[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode((payload_segment + padding).encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def is_microsoft_guest_upn(value: str) -> bool:
    text = str(value or "").strip().lower()
    return "#ext#" in text or text.endswith(".onmicrosoft.com")


def normalize_microsoft_display_email(value: str) -> str:
    text = str(value or "").strip().lower()
    if "#ext#@" not in text:
        return text
    local_part = text.split("#ext#@", 1)[0]
    if "_" not in local_part:
        return text
    mailbox_local, mailbox_domain = local_part.split("_", 1)
    if not mailbox_local or not mailbox_domain or "." not in mailbox_domain:
        return text
    return f"{mailbox_local}@{mailbox_domain}"


def resolve_microsoft_account_email(userinfo: Dict[str, Any], token_payload: Dict[str, Any]) -> str:
    claims = decode_jwt_payload(str(token_payload.get("id_token", "")))
    candidates = [
        str(userinfo.get("mail") or "").strip().lower(),
        str(claims.get("preferred_username") or "").strip().lower(),
        str(claims.get("email") or "").strip().lower(),
        str(claims.get("upn") or "").strip().lower(),
        str(userinfo.get("userPrincipalName") or "").strip().lower(),
    ]
    candidates = [candidate for candidate in candidates if candidate and "@" in candidate]
    for candidate in candidates:
        if not is_microsoft_guest_upn(candidate):
            return candidate
    return candidates[0] if candidates else ""


def default_profile_settings() -> Dict[str, str]:
    settings = {
        "FIRST_NAME": "",
        "LAST_NAME": "",
        "BIRTHDAY": "",
        "GENDER": "",
        "HOW_TO_SEEN": "false",
        "TERMS_ACCEPTED_AT": "",
        "PRIVACY_ACCEPTED_AT": "",
        "TERMS_VERSION_ACCEPTED": "",
        "PRIVACY_VERSION_ACCEPTED": "",
        "EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM": "false",
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "OPENAI_MODEL": "gpt-5.1",
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


def normalize_openai_model(value: Any) -> str:
    model = str(value or "").strip()
    # Legacy deployments defaulted to gpt-4o. Normalize those defaults to gpt-5.1.
    if not model or model == "gpt-4o":
        return "gpt-5.1"
    return model


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


def split_display_name(display_name: str) -> tuple[str, str]:
    parts = [part for part in str(display_name or "").strip().split() if part]
    if not parts:
        return "", ""
    return parts[0], " ".join(parts[1:])


def apply_profile_name_defaults(settings: Dict[str, str], display_name: str) -> Dict[str, str]:
    merged = dict(settings)
    existing_first = str(merged.get("FIRST_NAME", "") or "").strip()
    existing_last = str(merged.get("LAST_NAME", "") or "").strip()
    if existing_first or existing_last:
        return merged
    first_name, last_name = split_display_name(display_name)
    if first_name:
        merged["FIRST_NAME"] = first_name
    if last_name:
        merged["LAST_NAME"] = last_name
    return merged


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
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    preferences = parse_summary_style_preferences(settings)
    preferences.append(preference)
    settings["SUMMARY_STYLE_PREFERENCES"] = encode_summary_style_preferences(preferences)
    profile["settings"] = settings
    save_profile(profile)
    return parse_summary_style_preferences(settings)


def remove_summary_style_preference(user_id: str, preference: str) -> List[str]:
    profile = load_profile_or_404(user_id)
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
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
    mailbox_connected = (
        str(settings.get("MAILBOX_CONNECTION_CONFIRMED", "false")).lower() == "true"
        and bool(str(settings.get("IMAP_USER", "")).strip())
        and bool(str(settings.get("IMAP_PASSWORD", "")).strip())
    )
    return {
        "first_name": settings.get("FIRST_NAME", ""),
        "last_name": settings.get("LAST_NAME", ""),
        "birthday": settings.get("BIRTHDAY", ""),
        "gender": settings.get("GENDER", ""),
        "how_to_seen": str(settings.get("HOW_TO_SEEN", "false")).lower() == "true",
        "terms_accepted": bool(str(settings.get("TERMS_ACCEPTED_AT", "")).strip()),
        "privacy_accepted": bool(str(settings.get("PRIVACY_ACCEPTED_AT", "")).strip()),
        "terms_accepted_at": settings.get("TERMS_ACCEPTED_AT", ""),
        "privacy_accepted_at": settings.get("PRIVACY_ACCEPTED_AT", ""),
        "terms_version": settings.get("TERMS_VERSION_ACCEPTED", "") or TERMS_VERSION,
        "privacy_version": settings.get("PRIVACY_VERSION_ACCEPTED", "") or PRIVACY_VERSION,
        "attachment_ai_enabled": str(settings.get("EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM", "false")).lower() == "true",
        "openai_model": normalize_openai_model(settings.get("OPENAI_MODEL", "gpt-5.1")),
        "summary_style_preferences": parse_summary_style_preferences(settings),
        "imap_user": settings.get("IMAP_USER", ""),
        "imap_server": settings.get("IMAP_SERVER", ""),
        "imap_port": settings.get("IMAP_PORT", ""),
        "mailbox_connected": mailbox_connected,
    }


def profile_update_to_settings(update: ProfileUpdateRequest, existing: Dict[str, str]) -> Dict[str, str]:
    settings = dict(existing)
    if update.first_name.strip():
        settings["FIRST_NAME"] = update.first_name.strip()
    if update.last_name.strip():
        settings["LAST_NAME"] = update.last_name.strip()
    if update.attachment_ai_enabled is not None:
        settings["EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM"] = "true" if update.attachment_ai_enabled else "false"
    if update.openai_model.strip():
        settings["OPENAI_MODEL"] = normalize_openai_model(update.openai_model.strip())
    if update.imap_server.strip():
        settings["IMAP_SERVER"] = update.imap_server.strip()
    if update.imap_port.strip():
        settings["IMAP_PORT"] = update.imap_port.strip()
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


def merge_stored_settings(base: Dict[str, str], overrides: Dict[str, Any]) -> Dict[str, str]:
    merged = dict(base)
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        merged[str(key)] = str(value)
    return merged


def profile_requires_how_to_onboarding(profile: Dict[str, Any]) -> bool:
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    microsoft_connected = bool((profile.get("microsoft_oauth") or {}).get("refresh_token") or (profile.get("microsoft_oauth") or {}).get("access_token"))
    how_to_seen = str(settings.get("HOW_TO_SEEN", "false")).lower() == "true"
    return (google_connected or microsoft_connected) and not how_to_seen


def profile_requires_legal_acceptance(profile: Dict[str, Any]) -> bool:
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    return not (
        str(settings.get("TERMS_ACCEPTED_AT", "")).strip()
        and str(settings.get("PRIVACY_ACCEPTED_AT", "")).strip()
    )


def mark_legal_acceptance(settings: Dict[str, str]) -> Dict[str, str]:
    accepted_at = datetime.now().isoformat()
    settings["TERMS_ACCEPTED_AT"] = accepted_at
    settings["PRIVACY_ACCEPTED_AT"] = accepted_at
    settings["TERMS_VERSION_ACCEPTED"] = TERMS_VERSION
    settings["PRIVACY_VERSION_ACCEPTED"] = PRIVACY_VERSION
    return settings


def mark_profile_how_to_seen(user_id: str) -> Dict[str, Any]:
    profile = load_profile_or_404(user_id)
    profile["settings"] = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    profile["settings"]["HOW_TO_SEEN"] = "true"
    save_profile(profile)
    return profile


def apply_provider_defaults(settings: Dict[str, str], email: str, force_outlook: bool = False) -> Dict[str, str]:
    normalized = (email or "").strip().lower()
    merged = dict(settings)
    provider_defaults = {
        "IMAP_SERVER": "imap.263.net",
        "IMAP_PORT": "993",
        "SMTP_HOST": "smtp.263.net",
        "SMTP_PORT": "465",
        "IMAP_FOLDER": "INBOX",
    }

    if force_outlook:
        provider_defaults = {
            "IMAP_SERVER": "outlook.office365.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp-mail.outlook.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif normalized.endswith("@gmail.com"):
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

    if provider_defaults:
        for key, value in provider_defaults.items():
            if not merged.get(key):
                merged[key] = value
    return merged


def row_to_profile(row: sqlite3.Row) -> Dict[str, Any]:
    settings = merge_stored_settings(
        default_profile_settings(),
        decrypt_json_payload(row["settings_json"] or "{}", APP_STORAGE_DIR),
    )
    google_oauth = decrypt_json_payload(row["google_oauth_json"] or "{}", APP_STORAGE_DIR)
    microsoft_oauth = decrypt_json_payload(row["microsoft_oauth_json"] or "{}", APP_STORAGE_DIR)
    settings = apply_provider_defaults(
        settings,
        row["email"],
        force_outlook=str((microsoft_oauth or {}).get("provider", "")).strip().lower() == "microsoft",
    )
    settings["OPENAI_MODEL"] = normalize_openai_model(settings.get("OPENAI_MODEL"))
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
    payload["settings"] = merge_stored_settings(default_profile_settings(), payload.get("settings") or {})
    payload["settings"] = apply_provider_defaults(
        payload["settings"],
        payload.get("email", ""),
        force_outlook=str((payload.get("microsoft_oauth") or {}).get("provider", "")).strip().lower() == "microsoft",
    )
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
    if isinstance(profile.get("settings"), dict):
        profile["settings"]["OPENAI_MODEL"] = normalize_openai_model((profile.get("settings") or {}).get("OPENAI_MODEL"))
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
    response_settings = profile_settings_to_response(settings)
    if google_connected or microsoft_connected:
        response_settings["mailbox_connected"] = True
    response_email = profile.get("email", "")
    if microsoft_connected:
        oauth_email = str((profile.get("microsoft_oauth") or {}).get("email", "")).strip()
        if oauth_email:
            response_email = oauth_email
        response_email = normalize_microsoft_display_email(response_email)
    return {
        "user_id": profile["user_id"],
        "email": response_email,
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "contacts": contacts,
        "contact_profiles": contact_profiles,
        "google_connected": google_connected,
        "microsoft_connected": microsoft_connected,
        "auth_provider": auth_provider,
        "settings": response_settings,
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


def set_session_cookie(response: Response, session_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_COOKIE_MAX_AGE_SECONDS,
        secure=SESSION_COOKIE_SECURE,
        domain=SESSION_COOKIE_DOMAIN,
    )


def create_session(response: Response, user_id: str) -> str:
    session_token = secrets.token_urlsafe(32)
    with get_db_connection() as connection:
        connection.execute(
            "INSERT INTO sessions (session_token, user_id, created_at) VALUES (?, ?, ?)",
            (session_token, user_id, datetime.now().isoformat()),
        )
    set_session_cookie(response, session_token)
    return session_token


def refresh_session_cookie(response: Response, request: Request) -> None:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        set_session_cookie(response, session_token)


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
        settings = {**default_profile_settings(), **(profile.get("settings") or {})}
        settings["OPENAI_MODEL"] = normalize_openai_model(settings.get("OPENAI_MODEL"))
        return settings

    env_path = get_env_path_for_user(user_id)
    settings = {**default_profile_settings(), **read_env_key_values(env_path)}
    settings["OPENAI_MODEL"] = normalize_openai_model(settings.get("OPENAI_MODEL"))
    return settings


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
    existing_contacts = set(
        item.strip()
        for item in get_settings_for_user(resolved_user_id).get("WHITELIST_SENDERS", "").split(",")
        if item.strip()
    )
    cleaned_contacts = [contact.strip().lower() for contact in payload.contacts if contact.strip()]
    invalid_contacts = [contact for contact in cleaned_contacts if not is_valid_email(contact)]
    if invalid_contacts:
        raise HTTPException(status_code=400, detail="Incorrect email.")
    set_contacts_for_user(resolved_user_id, cleaned_contacts)
    settings = get_settings_for_user(resolved_user_id)
    added_contacts = [contact for contact in cleaned_contacts if contact not in existing_contacts]
    if added_contacts:
        track_analytics_event(
            resolved_user_id,
            "contact_added",
            {"count": len(added_contacts), "contacts": added_contacts[:10]},
        )
    return {
        "user_id": resolved_user_id,
        "contacts": cleaned_contacts,
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
    payload.setdefault("read_at", "")
    payload.setdefault("done_at", "")
    return payload


def save_summary_json(summary_path: Path, payload: Dict[str, Any]) -> None:
    summary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_all_current_summaries_for_user(user_id: str) -> List[Dict[str, Any]]:
    tracked_contacts = {contact.strip().lower() for contact in get_contacts_for_user(user_id) if contact.strip()}

    def is_tracked_summary(summary: Dict[str, Any]) -> bool:
        sender = str(summary.get("sender", "") or "").strip().lower()
        return bool(sender and sender in tracked_contacts)

    json_summaries_dir = get_user_json_summaries_dir(user_id)
    if json_summaries_dir.exists():
        summary_files = sorted(json_summaries_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        return [
            summary
            for path in summary_files
            if not path.stem.startswith("overall_master_")
            for summary in [load_summary_json(path)]
            if is_tracked_summary(summary)
        ]

    summaries_dir = get_user_summaries_dir(user_id)
    if summaries_dir.exists():
        summary_files = sorted(summaries_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
        return [
            summary
            for path in summary_files
            for summary in [load_summary_file(path)]
            if is_tracked_summary(summary)
        ]

    return []


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
        "read_at": payload.get("read_at", ""),
        "done_at": payload.get("done_at", ""),
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


def parse_iso_timestamp(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=ZoneInfo("UTC"))
    return parsed.astimezone(ZoneInfo("UTC"))


def purge_old_read_source_data(user_id: str) -> None:
    summaries_dir = get_user_json_summaries_dir(user_id)
    emails_dir = get_user_json_emails_dir(user_id)
    if not summaries_dir.exists() or not emails_dir.exists():
        return

    cutoff = datetime.now(ZoneInfo("UTC")) - timedelta(days=READ_RETENTION_DAYS)
    email_refs: Dict[str, List[bool]] = {}

    for summary_path in summaries_dir.glob("*.json"):
        if summary_path.stem.startswith("overall_master_"):
            continue
        try:
            payload = load_summary_json(summary_path)
        except Exception:
            continue
        read_at = parse_iso_timestamp(payload.get("read_at"))
        done_at = parse_iso_timestamp(payload.get("done_at"))
        eligible = bool(
            (read_at and read_at <= cutoff)
            or (done_at and done_at <= cutoff)
        )
        for email_id in payload.get("source_email_file_ids", []) or []:
            email_text = str(email_id).strip()
            if email_text:
                email_refs.setdefault(email_text, []).append(eligible)

    purgeable_email_ids = {
        email_id
        for email_id, flags in email_refs.items()
        if flags and all(flags)
    }

    for email_id in purgeable_email_ids:
        email_path = emails_dir / f"{email_id}.json"
        if not email_path.exists():
            continue
        try:
            email_payload = load_email_json(email_path)
        except Exception:
            continue
        if email_payload.get("content_purged_at"):
            continue

        attachment_paths: List[Path] = []
        for message in email_payload.get("thread", []) or []:
            for attachment in message.get("attachments", []) or []:
                saved_path = str(attachment.get("saved_path", "") or "").strip()
                if saved_path:
                    attachment_paths.append(Path(saved_path))

        for path in attachment_paths:
            try:
                resolved = path.resolve() if path.is_absolute() else (BASE_DIR / path).resolve()
                resolved.unlink(missing_ok=True)
            except Exception:
                continue

        for message in email_payload.get("thread", []) or []:
            message["body"] = ""
            message["attachments"] = []
        email_payload["raw_path"] = ""
        email_payload["content_purged_at"] = datetime.now().isoformat()
        email_payload["content_retention_policy"] = (
            f"Source bodies and attachments purged {READ_RETENTION_DAYS} days after read or done."
        )
        email_path.write_text(json.dumps(email_payload, indent=2, ensure_ascii=False), encoding="utf-8")


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


def render_inline_markdown_html(text: str) -> str:
    escaped = escape(str(text or ""))
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


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


@app.api_route("/public-report", methods=["GET", "HEAD"])
def get_public_report(
    user_id: str = Query(...),
    path: str = Query(...),
    expires: int = Query(...),
    sig: str = Query(...),
) -> FileResponse:
    if expires < int(datetime.now().timestamp()):
        raise HTTPException(status_code=403, detail="Public report link has expired.")
    expected_sig = sign_public_report_token(user_id, path, expires)
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=403, detail="Invalid public report signature.")

    requested_path = (PUBLIC_REPORTS_DIR / path).resolve()
    try:
        requested_path.relative_to((PUBLIC_REPORTS_DIR / user_id).resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid public report path.")

    if not requested_path.exists() or not requested_path.is_file():
        raise HTTPException(status_code=404, detail="Public report file not found.")

    return FileResponse(
        requested_path,
        filename=requested_path.name,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{requested_path.name}"'},
    )


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
    removed_uids: List[str] = [str(uid).strip() for uid in summary_payload.get("source_uids", []) or [] if str(uid).strip()]
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
        removed_uid_set = set(uid for uid in removed_uids if uid)
        remaining_uids = [uid for uid in load_processed_uids_for_user(user_id) if uid not in removed_uid_set]
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
    google_oauth = profile.get("google_oauth") or {}
    smtp_host = settings.get("SMTP_HOST", "")
    smtp_port = int(settings.get("SMTP_PORT", "465") or 465)
    smtp_user = settings.get("SMTP_USER", "")
    smtp_password = settings.get("SMTP_PASSWORD", "")
    recipient = settings.get("SUMMARY_RECIPIENT") or settings.get("IMAP_USER") or profile.get("email", "")

    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        raise HTTPException(status_code=400, detail="Email sending is not configured for this account yet.")
    if not is_valid_email(recipient):
        raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = summary.get("title", f"Summary: {summary.get('summary_id', '')}")
    msg["From"] = smtp_user
    msg["To"] = recipient
    text_parts: List[str] = [
        str(summary.get("title") or summary.get("summary_id") or "Summary").strip(),
        "",
    ]
    for key in [
        "executive_summary",
        "main_topics",
        "new_developments",
        "action_items",
        "deadlines",
        "attachment_summary",
        "bottom_line",
    ]:
        value = str(summary.get(key) or "").strip()
        if not value:
            continue
        label = key.replace("_", " ").title()
        text_parts.append(f"{label}:")
        text_parts.append(re.sub(r"\*\*(.+?)\*\*", r"\1", value))
        text_parts.append("")
    msg.attach(MIMEText(_to_ascii_safe("\n".join(text_parts).strip()), "plain", "utf-8"))
    msg.attach(MIMEText(render_summary_email_html(summary), "html", "utf-8"))

    if str(google_oauth.get("provider", "")).strip().lower() == "google":
        if not google_oauth_has_scope(profile, REQUIRED_GOOGLE_SEND_SCOPE):
            raise HTTPException(
                status_code=400,
                detail="Google email sending needs to be refreshed for this account. Sign out and sign back in with Google to grant send permissions.",
            )
        if not is_valid_email(recipient):
            raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")
        access_token = refresh_google_access_token(profile)
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        post_json_with_bearer(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            access_token,
            {"raw": raw_message},
            error_prefix="Failed to send Gmail message",
        )
        return {"recipient": recipient, "subject": msg["Subject"]}

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


def build_scheduled_report_markdown(summaries: List[Dict[str, Any]]) -> str:
    blocks: List[str] = []

    section_map = [
        ("Executive Summary", "executive_summary"),
        ("Main Topics", "main_topics"),
        ("New Developments", "new_developments"),
        ("Action Items / Asks", "action_items"),
        ("Deadlines / Dates / Meetings", "deadlines"),
        ("Attachment Summary", "attachment_summary"),
        ("Bottom Line", "bottom_line"),
    ]

    for summary in summaries:
        title = clean_summary_title(summary.get("title", ""), summary.get("summary_id", "Summary"))
        parts = [f"## {title}"]

        if summary.get("updated_at"):
            parts.append(f"Updated: {summary.get('updated_at')}")

        for section_title, key in section_map:
            content = str(summary.get(key, "") or "").strip()
            if not content:
                continue
            parts.append(f"### {section_title}")
            parts.append(content)

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
            html_parts.append(
                f"<p style='margin:0 0 10px 0; line-height:1.65; color:#191917; font-size:15px;'>{render_inline_markdown_html(line)}</p>"
            )
        if bullet_lines:
            html_parts.append(
                "<ul style='margin:0; padding-left:22px;'>"
                + "".join(
                    f"<li style='margin:0 0 8px 0; line-height:1.6; color:#191917; font-size:15px;'>{render_inline_markdown_html(item)}</li>"
                    for item in bullet_lines
                )
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
            f"<h3 style='margin:0 0 8px 0; font-size:17px; color:#111; letter-spacing:-0.02em;'>{escape(section_title)}</h3>"
            f"<div style='background:linear-gradient(180deg, #ffffff 0%, #f5f3ed 100%); border:1px solid #e3e3e8; border-radius:16px; padding:16px;'>{block}</div>"
            f"</section>"
        )

    if not section_html and sections:
        for section_title, section_content in sections.items():
            block = render_block(section_content)
            if not block:
                continue
            section_html.append(
                f"<section style='margin:0 0 18px 0;'>"
                f"<h3 style='margin:0 0 8px 0; font-size:17px; color:#111; letter-spacing:-0.02em;'>{escape(section_title)}</h3>"
                f"<div style='background:linear-gradient(180deg, #ffffff 0%, #f5f3ed 100%); border:1px solid #e3e3e8; border-radius:16px; padding:16px;'>{block}</div>"
                f"</section>"
            )

    if not section_html:
        section_html.append(
            f"<section style='margin:0 0 18px 0;'>"
            f"<div style='background:linear-gradient(180deg, #ffffff 0%, #f5f3ed 100%); border:1px solid #e3e3e8; border-radius:16px; padding:16px;'>"
            f"{render_block(markdown)}"
            f"</div></section>"
        )

    return (
        "<html><body style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; color:#111; "
        "max-width:760px; margin:0 auto; padding:24px; background:#fff;'>"
        f"<h1 style='margin:0 0 24px 0; font-size:30px; letter-spacing:-0.04em; color:#111;'>{escape(title)}</h1>"
        + "".join(section_html)
        + "</body></html>"
    )


def send_combined_report_via_smtp(user_id: str, title: str, markdown: str, recipient_override: Optional[str] = None) -> Dict[str, str]:
    settings = get_settings_for_user(user_id)
    profile = load_profile(user_id) or {}
    google_oauth = profile.get("google_oauth") or {}
    smtp_host = settings.get("SMTP_HOST", "")
    smtp_port = int(settings.get("SMTP_PORT", "465") or 465)
    smtp_user = settings.get("SMTP_USER", "")
    smtp_password = settings.get("SMTP_PASSWORD", "")
    recipient = recipient_override or settings.get("SUMMARY_RECIPIENT") or settings.get("IMAP_USER") or profile.get("email", "")

    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        raise HTTPException(status_code=400, detail="Email sending is not configured for this account yet.")
    if not is_valid_email(recipient):
        raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = title
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg.attach(MIMEText(render_markdown_report_text(title, markdown, max_chars=20000), "plain", "utf-8"))
    msg.attach(MIMEText(render_markdown_report_email_html(title, markdown), "html", "utf-8"))

    if str(google_oauth.get("provider", "")).strip().lower() == "google":
        if not google_oauth_has_scope(profile, REQUIRED_GOOGLE_SEND_SCOPE):
            raise HTTPException(
                status_code=400,
                detail="Google email sending needs to be refreshed for this account. Sign out and sign back in with Google to grant send permissions.",
            )
        access_token = refresh_google_access_token(profile)
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        post_json_with_bearer(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            access_token,
            {"raw": raw_message},
            error_prefix="Failed to send Gmail message",
        )
        track_analytics_event(
            user_id,
            "report_delivered",
            {"delivery_channel": "email", "recipient": recipient, "title": title},
        )
        return {"recipient": recipient, "subject": msg["Subject"]}

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

    track_analytics_event(
        user_id,
        "report_delivered",
        {"delivery_channel": "email", "recipient": recipient, "title": title},
    )
    return {"recipient": recipient, "subject": msg["Subject"]}


def render_markdown_report_text(title: str, markdown: str, max_chars: int = 1400) -> str:
    sections = parse_markdown_sections(markdown)
    blocks: List[str] = [title.strip()]
    for section_title, section_content in sections.items():
        lines = [line.strip() for line in str(section_content or "").splitlines() if line.strip()]
        if not lines:
            continue
        blocks.append(f"{section_title}:")
        for line in lines:
            cleaned = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
            if cleaned.startswith("- "):
                blocks.append(f"• {cleaned[2:].strip()}")
            else:
                blocks.append(cleaned)
        blocks.append("")
    text = _to_ascii_safe("\n".join(blocks).strip())
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "\n... [continued in email/app]"
    return text


def paragraph_markup(text: str) -> str:
    escaped = escape(str(text or ""))
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)


def generate_report_pdf(user_id: str, title: str, markdown: str) -> Path:
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    pdf_dir = PUBLIC_REPORTS_DIR / user_id
    pdf_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = pdf_dir / f"r_{timestamp}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#111111"),
        spaceAfter=18,
        alignment=TA_LEFT,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#111111"),
        spaceBefore=10,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=11,
        leading=16,
        textColor=colors.HexColor("#1a1a17"),
        spaceAfter=8,
    )

    sections = parse_markdown_sections(markdown)
    story: List[Any] = [Paragraph(paragraph_markup(title), title_style), Spacer(1, 0.08 * inch)]

    if not sections:
        sections = {"Report": markdown}

    for section_title, section_content in sections.items():
        lines = [line.strip() for line in str(section_content or "").splitlines() if line.strip()]
        if not lines:
            continue
        story.append(Paragraph(paragraph_markup(section_title), heading_style))
        bullet_lines = [line[2:] for line in lines if line.startswith("- ")]
        plain_lines = [line for line in lines if not line.startswith("- ")]
        for line in plain_lines:
            story.append(Paragraph(paragraph_markup(line), body_style))
        if bullet_lines:
            bullet_items = [
                ListItem(Paragraph(paragraph_markup(item), body_style), leftIndent=6)
                for item in bullet_lines
            ]
            story.append(
                ListFlowable(
                    bullet_items,
                    bulletType="bullet",
                    start="circle",
                    leftIndent=14,
                    bulletFontName="Helvetica-Bold",
                )
            )
            story.append(Spacer(1, 0.06 * inch))

    document = SimpleDocTemplate(
        str(pdf_path),
        pagesize=LETTER,
        leftMargin=0.72 * inch,
        rightMargin=0.72 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.72 * inch,
    )
    document.build(story)
    return pdf_path


def sign_public_report_token(user_id: str, relative_path: str, expires_at: int) -> str:
    secret = get_app_config_value("EMAIL_SUMMARIZER_PUBLIC_REPORT_SECRET") or get_app_config_value("EMAIL_SUMMARIZER_ENCRYPTION_KEY")
    if not secret:
        raise HTTPException(status_code=500, detail="Public report signing secret is not configured.")
    payload = f"{user_id}:{relative_path}:{expires_at}"
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def build_public_report_url(user_id: str, pdf_path: Path, expires_in_seconds: int = 86400) -> str:
    if not PUBLIC_BASE_URL:
        raise HTTPException(status_code=500, detail="EMAIL_SUMMARIZER_PUBLIC_BASE_URL must be configured for SMS PDF delivery.")
    relative_path = str(pdf_path.relative_to(PUBLIC_REPORTS_DIR))
    expires_at = int((datetime.now() + timedelta(seconds=expires_in_seconds)).timestamp())
    signature = sign_public_report_token(user_id, relative_path, expires_at)
    return f"{PUBLIC_BASE_URL}/public-report?user_id={quote(user_id)}&path={quote(relative_path)}&expires={expires_at}&sig={signature}"


def should_attach_pdf_to_message(pdf_path: Path) -> bool:
    try:
        size_bytes = pdf_path.stat().st_size
    except Exception:
        return False
    return size_bytes <= 600 * 1024


def send_text_via_twilio(phone_number: str, body: str, media_url: Optional[str] = None) -> Dict[str, str]:
    account_sid = get_app_config_value("TWILIO_ACCOUNT_SID")
    auth_token = get_app_config_value("TWILIO_AUTH_TOKEN")
    from_number = get_app_config_value("TWILIO_FROM_NUMBER")
    messaging_service_sid = get_app_config_value("TWILIO_MESSAGING_SERVICE_SID")

    if not account_sid or not auth_token:
        raise HTTPException(status_code=500, detail="Twilio is not configured yet.")
    if not from_number and not messaging_service_sid:
        raise HTTPException(status_code=500, detail="Set TWILIO_FROM_NUMBER or TWILIO_MESSAGING_SERVICE_SID first.")
    if not is_valid_e164_phone(phone_number):
        raise HTTPException(status_code=400, detail="Phone number must be in E.164 format, for example +14155550123.")

    payload = {
        "To": phone_number,
        "Body": body,
    }
    if media_url:
        payload["MediaUrl"] = media_url
    if messaging_service_sid:
        payload["MessagingServiceSid"] = messaging_service_sid
    else:
        payload["From"] = from_number

    auth_header = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    request = UrlRequest(
        f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
        data=urlencode(payload).encode("utf-8"),
        headers={
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload_text = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"Twilio SMS send failed: {payload_text}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Twilio SMS send failed: {exc}") from exc

    return {
        "recipient_phone": phone_number,
        "message_sid": str(response_payload.get("sid", "")),
        "delivery_channel": "sms",
    }


def send_combined_report_via_sms(user_id: str, title: str, markdown: str, phone_number: str) -> Dict[str, Any]:
    pdf_path = generate_report_pdf(user_id, title, markdown)
    public_pdf_url = build_public_report_url(user_id, pdf_path)
    message_body = render_markdown_report_text(title, markdown, max_chars=240) + f"\n\nOpen PDF: {public_pdf_url}"
    media_url = public_pdf_url if should_attach_pdf_to_message(pdf_path) else None
    delivery = send_text_via_twilio(phone_number, message_body, media_url=media_url)
    track_analytics_event(
        user_id,
        "report_delivered",
        {"delivery_channel": "sms", "recipient_phone": phone_number, "title": title, "pdf_attached": bool(media_url)},
    )
    return {
        "pdf_url": public_pdf_url,
        "pdf_attached": bool(media_url),
        **delivery,
    }


def process_due_schedule(schedule_id: str) -> None:
    with SCHEDULE_RUNNER_LOCK:
        if schedule_id in ACTIVE_SCHEDULE_RUNS:
            return
        ACTIVE_SCHEDULE_RUNS.add(schedule_id)

    try:
        with get_db_connection() as connection:
            schedule = connection.execute(
                "SELECT * FROM report_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
        if not schedule or not bool(schedule["active"]):
            return

        user_id = str(schedule["user_id"])
        days_back = int(schedule["days_back"])
        delivery_channel = str(schedule["delivery_channel"] or "email")
        recipient_email = str(schedule["recipient_email"] or "").strip()
        recipient_phone = str(schedule["recipient_phone"] or "").strip()

        execute_summarizer_run(user_id, days_back)

        summaries = load_all_current_summaries_for_user(user_id)
        if summaries:
            markdown = build_scheduled_report_markdown(summaries)
            title = str(schedule["name"] or "Scheduled Report").strip() or "Scheduled Report"
            if delivery_channel == "sms" and recipient_phone:
                send_combined_report_via_sms(user_id, title, markdown, recipient_phone)
            elif recipient_email:
                send_combined_report_via_smtp(user_id, title, markdown, recipient_override=recipient_email)

        now_dt = datetime.now(ZoneInfo(str(schedule["timezone"] or "America/Los_Angeles")))
        next_run_at = compute_next_schedule_run(
            now=now_dt,
            timezone_name=str(schedule["timezone"] or "America/Los_Angeles"),
            interval_value=int(schedule["interval_value"]),
            interval_unit=str(schedule["interval_unit"]),
            preferred_hour=int(schedule["preferred_hour"]),
            preferred_minute=int(schedule["preferred_minute"]),
            last_run_at=now_dt.isoformat(),
        )
        with get_db_connection() as connection:
            connection.execute(
                """
                UPDATE report_schedules
                SET last_run_at = ?, next_run_at = ?, updated_at = ?
                WHERE schedule_id = ?
                """,
                (now_dt.isoformat(), next_run_at, datetime.now().isoformat(), schedule_id),
            )
    finally:
        with SCHEDULE_RUNNER_LOCK:
            ACTIVE_SCHEDULE_RUNS.discard(schedule_id)


def schedule_runner_loop() -> None:
    while True:
        try:
            now_utc = datetime.now(ZoneInfo("UTC"))
            with get_db_connection() as connection:
                rows = connection.execute(
                    "SELECT schedule_id, next_run_at FROM report_schedules WHERE active = 1"
                ).fetchall()
            for row in rows:
                next_run_raw = str(row["next_run_at"] or "").strip()
                if not next_run_raw:
                    continue
                try:
                    next_run = datetime.fromisoformat(next_run_raw)
                except Exception:
                    continue
                if next_run.tzinfo is None:
                    next_run = next_run.replace(tzinfo=ZoneInfo("UTC"))
                else:
                    next_run = next_run.astimezone(ZoneInfo("UTC"))
                if next_run <= now_utc:
                    threading.Thread(target=process_due_schedule, args=(str(row["schedule_id"]),), daemon=True).start()
        except Exception:
            pass
        threading.Event().wait(60)


threading.Thread(target=schedule_runner_loop, daemon=True).start()


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
    model = normalize_openai_model(settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.1")
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


@app.post("/summaries/combined/send-text")
def send_combined_summary_text(payload: CombinedSummaryTextRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    combined = generate_combined_summary_content(resolved_user_id, payload.summary_ids, request)
    phone_number = str(payload.phone_number or "").strip()
    if not phone_number:
        raise HTTPException(status_code=400, detail="phone_number is required for SMS delivery.")
    pdf_path = generate_report_pdf(resolved_user_id, combined["title"], combined["combined_markdown"])
    public_pdf_url = build_public_report_url(resolved_user_id, pdf_path)
    message_body = (
        render_markdown_report_text(combined["title"], combined["combined_markdown"], max_chars=240)
        + f"\n\nOpen PDF: {public_pdf_url}"
    )
    media_url = public_pdf_url if should_attach_pdf_to_message(pdf_path) else None
    delivery = send_text_via_twilio(
        phone_number,
        message_body,
        media_url=media_url,
    )
    return {
        "success": True,
        "user_id": resolved_user_id,
        "summary_ids": combined["summary_ids"],
        "count": combined["count"],
        "pdf_url": public_pdf_url,
        "pdf_attached": bool(media_url),
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
    model = normalize_openai_model(settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.1")
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

    track_analytics_event(
        resolved_user_id,
        "refinement_used",
        {
            "title": title,
            "instruction_length": len(instructions),
            "saved_preference": bool(payload.save_preference),
        },
    )

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


@app.post("/bug-reports")
def create_bug_report(payload: BugReportRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    profile = load_profile_or_404(resolved_user_id)
    title = str(payload.title or "").strip()
    description = str(payload.description or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Bug title cannot be empty.")
    if not description:
        raise HTTPException(status_code=400, detail="Bug description cannot be empty.")

    bug_id = secrets.token_hex(12)
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO bug_reports (bug_id, user_id, email, title, description, page_url, user_agent, created_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bug_id,
                resolved_user_id,
                str(profile.get("email", "") or "").strip(),
                title,
                description,
                str(payload.page_url or "").strip(),
                str(payload.user_agent or "").strip(),
                datetime.now().isoformat(),
                json.dumps(payload.metadata or {}, ensure_ascii=False),
            ),
        )

    track_analytics_event(
        resolved_user_id,
        "bug_reported",
        {"bug_id": bug_id, "title": title[:120], "page_url": str(payload.page_url or "").strip()},
    )
    return {"success": True, "bug_id": bug_id}


def execute_summarizer_run(user_id: str, days_back: int) -> Dict[str, Any]:
    before_count = len(load_all_current_summaries_for_user(user_id))
    env = os.environ.copy()
    env["CLIENT_NAME"] = user_id
    env["PROFILE_USER_ID"] = user_id
    env["DAYS_BACK"] = str(days_back)

    result = subprocess.run(
        ["python3", "email_v13.py"],
        cwd=str(BASE_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )

    parsed_stats: Dict[str, Any] = {}
    for line in reversed(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            parsed_payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_payload, dict) and "stats" in parsed_payload:
            parsed_stats = parsed_payload.get("stats") or {}
            break

    result_payload = {
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "stats": parsed_stats,
        "success": result.returncode == 0,
    }
    after_count = len(load_all_current_summaries_for_user(user_id))
    if result_payload["success"] and before_count == 0 and after_count > 0 and not analytics_event_exists(user_id, "first_summary_generated"):
        track_analytics_event(
            user_id,
            "first_summary_generated",
            {"days_back": days_back, "summary_count": after_count},
        )
    return result_payload


def launch_summarizer_job(user_id: str, days_back: int) -> Dict[str, Any]:
    job_id = secrets.token_hex(12)
    started_at = datetime.now().isoformat()
    initial_job = {
        "job_id": job_id,
        "user_id": user_id,
        "days_back": days_back,
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "stats": {},
        "success": False,
    }
    with RUN_JOB_LOCK:
        RUN_JOBS[job_id] = dict(initial_job)

    def worker() -> None:
        try:
            result_payload = execute_summarizer_run(user_id, days_back)
            final_job = {
                "job_id": job_id,
                "user_id": user_id,
                "days_back": days_back,
                "status": "completed" if result_payload["success"] else "failed",
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                **result_payload,
            }
        except subprocess.TimeoutExpired as exc:
            final_job = {
                "job_id": job_id,
                "user_id": user_id,
                "days_back": days_back,
                "status": "failed",
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "returncode": None,
                "stdout": (exc.stdout or "")[-4000:],
                "stderr": ((exc.stderr or "") + "\nTimed out after 600 seconds.")[-4000:],
                "stats": {},
                "success": False,
            }
        except Exception as exc:
            final_job = {
                "job_id": job_id,
                "user_id": user_id,
                "days_back": days_back,
                "status": "failed",
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "returncode": None,
                "stdout": "",
                "stderr": str(exc),
                "stats": {},
                "success": False,
            }

        with RUN_JOB_LOCK:
            RUN_JOBS[job_id] = final_job

    threading.Thread(target=worker, daemon=True).start()
    return dict(initial_job)


@app.get("/run-summarizer/status/{job_id}")
def get_run_summarizer_status(job_id: str, request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    with RUN_JOB_LOCK:
        job = dict(RUN_JOBS.get(job_id) or {})
    if not job or job.get("user_id") != resolved_user_id:
        raise HTTPException(status_code=404, detail="Run job not found.")
    return job


@app.get("/run-summarizer/active")
def get_active_run_summarizer_job(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    active_job: Dict[str, Any] = {}
    with RUN_JOB_LOCK:
        for job in RUN_JOBS.values():
            if job.get("user_id") != resolved_user_id:
                continue
            if job.get("status") != "running":
                continue
            if not active_job or str(job.get("started_at") or "") > str(active_job.get("started_at") or ""):
                active_job = dict(job)

    return {
        "user_id": resolved_user_id,
        "job": active_job or None,
    }


@app.post("/run-summarizer")
def run_summarizer(payload: RunSummarizerRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    profile = load_profile_or_404(resolved_user_id)
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    if google_connected and not google_oauth_has_scope(profile, REQUIRED_GOOGLE_READ_SCOPE):
        raise HTTPException(
            status_code=400,
            detail="Google mailbox access needs to be refreshed for this account. Sign out and sign back in with Google to grant Gmail permissions.",
        )
    return launch_summarizer_job(resolved_user_id, payload.days_back)


@app.get("/summaries")
def list_summaries(request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    purge_old_read_source_data(user_id)
    contact_profiles = parse_contact_profiles(get_settings_for_user(user_id))
    tracked_contacts = {contact.strip().lower() for contact in get_contacts_for_user(user_id) if contact.strip()}

    def is_tracked_summary(summary: Dict[str, Any]) -> bool:
        sender = str(summary.get("sender", "") or "").strip().lower()
        return bool(sender and sender in tracked_contacts)

    json_summaries_dir = get_user_json_summaries_dir(user_id)
    summaries_dir = get_user_summaries_dir(user_id)
    if json_summaries_dir.exists():
        summary_files = sorted(json_summaries_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        summaries = [
            apply_contact_profile_to_summary(summary, contact_profiles)
            for path in summary_files
            if not path.stem.startswith("overall_master_")
            for summary in [load_summary_json_preview(path)]
            if is_tracked_summary(summary)
        ]
        return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "json"}

    if not summaries_dir.exists():
        return {"user_id": user_id, "summaries": [], "message": "No current summaries."}

    summary_files = sorted(summaries_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    summaries = [
        summary
        for path in summary_files
        for summary in [load_summary_file(path)]
        if is_tracked_summary(summary)
    ]

    for summary in summaries:
        summary.pop("content_markdown", None)

    return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "markdown"}


@app.get("/summaries/{summary_id}")
def get_summary(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    purge_old_read_source_data(user_id)
    contact_profiles = parse_contact_profiles(get_settings_for_user(user_id))
    json_summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if json_summary_path.exists():
        return apply_contact_profile_to_summary(load_summary_json(json_summary_path), contact_profiles)

    summary_path = get_user_summaries_dir(user_id) / f"{summary_id}.md"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    return load_summary_file(summary_path)


@app.get("/summaries/{summary_id}/thread")
def get_summary_thread(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    purge_old_read_source_data(user_id)
    summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    summary = load_summary_json(summary_path)
    email_ids = [str(email_id).strip() for email_id in summary.get("source_email_file_ids", []) or [] if str(email_id).strip()]
    threads: List[Dict[str, Any]] = []

    for email_id in email_ids:
        email_path = get_user_json_emails_dir(user_id) / f"{email_id}.json"
        if not email_path.exists():
            continue
        email_payload = load_email_json(email_path)
        threads.append(
            {
                "email_id": email_payload.get("email_id", email_id),
                "subject": email_payload.get("subject", ""),
                "sender": email_payload.get("sender", ""),
                "date": email_payload.get("date", ""),
                "thread": [
                    {
                        "message_id": message.get("message_id", ""),
                        "date": message.get("date", ""),
                        "from": message.get("sender", ""),
                        "to": message.get("to", ""),
                        "cc": message.get("cc", ""),
                        "subject": message.get("subject", ""),
                        "body": message.get("body", ""),
                    }
                    for message in email_payload.get("thread", []) or []
                ],
            }
        )

    return {
        "summary_id": summary_id,
        "title": summary.get("title", summary_id),
        "contact_label": summary.get("contact_label", ""),
        "email_record_count": len(threads),
        "threads": threads,
    }


@app.post("/summaries/{summary_id}/mark-read")
def mark_summary_read(summary_id: str, request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    payload = load_summary_json(summary_path)
    was_unread = not str(payload.get("read_at", "")).strip()
    if was_unread:
        payload["read_at"] = datetime.now().isoformat()
        save_summary_json(summary_path, payload)
        track_analytics_event(
            user_id,
            "summary_opened",
            {"summary_id": summary_id, "sender": str(payload.get("sender", "")).strip()},
        )

    purge_old_read_source_data(user_id)
    return {
        "success": True,
        "user_id": user_id,
        "summary_id": summary_id,
        "read_at": payload.get("read_at", ""),
    }


@app.post("/summaries/{summary_id}/mark-done")
def mark_summary_done(summary_id: str, payload: SummaryDoneRequest, request: Request) -> Dict[str, Any]:
    user_id = resolve_user_id(request, payload.user_id)
    summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail=f"Summary '{summary_id}' not found for user '{user_id}'.")

    summary_payload = load_summary_json(summary_path)
    is_done = bool(payload.done)
    summary_payload["done_at"] = datetime.now().isoformat() if is_done else ""
    save_summary_json(summary_path, summary_payload)
    purge_old_read_source_data(user_id)
    return {
        "success": True,
        "user_id": user_id,
        "summary_id": summary_id,
        "done_at": summary_payload.get("done_at", ""),
    }


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
