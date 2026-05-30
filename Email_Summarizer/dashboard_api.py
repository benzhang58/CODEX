import json
import logging
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
import time
import unicodedata
import base64
import socket
from functools import lru_cache
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
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

logger = logging.getLogger("discere.dashboard")
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
APP_ENVIRONMENT = os.getenv("RENDER_SERVICE_NAME") or os.getenv("RENDER") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or ""
_cookie_secure_env = os.getenv("EMAIL_SUMMARIZER_COOKIE_SECURE")
SESSION_COOKIE_SECURE = (
    _cookie_secure_env.lower() == "true"
    if _cookie_secure_env is not None
    else PUBLIC_BASE_URL.startswith("https://") or bool(os.getenv("RENDER"))
)
SESSION_COOKIE_DOMAIN = os.getenv("EMAIL_SUMMARIZER_COOKIE_DOMAIN", "").strip() or None
RUN_JOB_LOCK = threading.Lock()
RUN_JOBS: Dict[str, Dict[str, Any]] = {}
SCHEDULE_RUNNER_LOCK = threading.Lock()
ACTIVE_SCHEDULE_RUNS: set[str] = set()
RATE_LIMIT_BUCKETS: Dict[str, List[float]] = {}
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_RULES = [
    ("POST", "/auth/login", 20, 300),
    ("POST", "/auth/signup", 10, 3600),
    ("POST", "/public-chat", 20, 3600),
    ("POST", "/run-summarizer", 12, 3600),
    ("POST", "/chat", 30, 3600),
    ("POST", "/summaries/refine", 20, 3600),
    ("POST", "/summaries/combined/send-email", 20, 3600),
    ("POST", "/summaries/combined/send-text", 10, 3600),
    ("POST", "/bug-reports", 8, 3600),
]
MAX_REQUEST_BODY_BYTES = int(os.getenv("EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))
MAX_PUBLIC_CHAT_QUESTION_CHARS = 800
MAX_CHAT_QUESTION_CHARS = 1200
MAX_REFINE_MARKDOWN_CHARS = 50000
MAX_REFINE_INSTRUCTIONS_CHARS = 2000
MAX_BUG_TITLE_CHARS = 160
MAX_BUG_DESCRIPTION_CHARS = 5000
MAX_SUMMARY_IDS_PER_REQUEST = 50
MONITORING_ALERT_SEVERITIES = {"error", "critical"}
MONITORING_ALERT_CATEGORIES = {
    "oauth",
    "summarizer",
    "data_isolation",
    "report_delivery",
    "abuse",
    "server_error",
    "security",
    "retention",
}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

app = FastAPI(title="Email Summarizer Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=APP_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_production_environment() -> bool:
    if PUBLIC_BASE_URL.startswith("https://"):
        return True
    return str(APP_ENVIRONMENT or "").lower() in {"1", "true", "production", "prod"} or bool(os.getenv("RENDER"))


def cors_origins_are_production_safe() -> bool:
    if not is_production_environment():
        return True
    allowed_local = {"http://127.0.0.1:8000", "http://localhost:8000"}
    non_local_origins = [origin for origin in APP_CORS_ORIGINS if origin not in allowed_local]
    if not non_local_origins:
        return False
    return "*" not in APP_CORS_ORIGINS and all(origin.startswith("https://") for origin in non_local_origins)


def configured_manual_mailbox_allowed_emails() -> set[str]:
    raw_value = os.getenv("EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS", "")
    return {
        item.strip().lower()
        for item in raw_value.split(",")
        if item.strip()
    }


def manual_signup_access_password() -> str:
    return os.getenv("EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD", "").strip()


def configured_vip_mailbox_email() -> str:
    return os.getenv("EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL", "").strip().lower()


def email_is_manual_mailbox_allowed(email: str) -> bool:
    normalized = str(email or "").strip().lower()
    return bool(normalized and normalized in configured_manual_mailbox_allowed_emails())


def email_is_configured_vip_mailbox(email: str) -> bool:
    normalized = str(email or "").strip().lower()
    vip_email = configured_vip_mailbox_email()
    return bool(normalized and vip_email and normalized == vip_email and email_is_manual_mailbox_allowed(normalized))


def profile_manual_mailbox_allowed(profile: Dict[str, Any]) -> bool:
    candidates = {
        str(profile.get("email", "") or "").strip().lower(),
        str((profile.get("google_oauth") or {}).get("email", "") or "").strip().lower(),
        str((profile.get("microsoft_oauth") or {}).get("email", "") or "").strip().lower(),
    }
    normalized_microsoft = normalize_microsoft_display_email(str((profile.get("microsoft_oauth") or {}).get("email", "") or ""))
    if normalized_microsoft:
        candidates.add(normalized_microsoft.strip().lower())
    allowed = configured_manual_mailbox_allowed_emails()
    return bool(allowed and (candidates & allowed))


def validate_manual_signup_access(email: str, provided_password: str) -> None:
    normalized = str(email or "").strip().lower()
    if not email_is_manual_mailbox_allowed(email):
        write_monitoring_event(
            "security",
            "manual_signup_email_not_allowlisted",
            "warning",
            metadata={"email": email},
        )
        raise HTTPException(
            status_code=403,
            detail="Manual account creation is available only for approved private clients. Use Google or Microsoft to log in.",
        )
    vip_email = configured_vip_mailbox_email()
    if not vip_email:
        write_monitoring_event(
            "security",
            "manual_signup_vip_email_missing",
            "error",
            metadata={"email": normalized},
        )
        raise HTTPException(
            status_code=503,
            detail="Private manual account setup is not configured yet. Contact Discere support.",
        )
    if normalized != vip_email:
        write_monitoring_event(
            "security",
            "manual_signup_not_configured_vip_email",
            "warning",
            metadata={"email": normalized},
        )
        raise HTTPException(
            status_code=403,
            detail="Private account creation is only available for the approved private client.",
        )
    expected = manual_signup_access_password()
    if not expected:
        write_monitoring_event(
            "security",
            "manual_signup_access_password_missing",
            "error",
            metadata={"email": normalized},
        )
        raise HTTPException(
            status_code=503,
            detail="Private manual account setup is not configured yet. Contact Discere support.",
        )
    if not hmac.compare_digest(str(provided_password or ""), expected):
        write_monitoring_event(
            "security",
            "manual_signup_access_denied",
            "warning",
            metadata={"email": email},
        )
        raise HTTPException(status_code=403, detail="Incorrect private signup access password.")


def request_contains_manual_mailbox_update(payload: "ProfileUpdateRequest") -> bool:
    return bool(str(payload.imap_password or "").strip() or str(payload.smtp_password or "").strip())


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def monitoring_enabled() -> bool:
    return os.getenv("EMAIL_SUMMARIZER_MONITORING_ENABLED", "true").lower() != "false"


def public_reports_enabled() -> bool:
    return os.getenv("EMAIL_SUMMARIZER_PUBLIC_REPORTS_ENABLED", "false").strip().lower() == "true"


SENSITIVE_METADATA_KEY_TERMS = ("token", "secret", "password", "authorization", "cookie", "api_key", "key")
SENSITIVE_TEXT_PATTERNS = [
    re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|AUTHORIZATION|COOKIE|API_KEY|KEY)[A-Z0-9_]*\b\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
    ),
    re.compile(
        r"(?i)((?:\"|')?(?:access_token|refresh_token|id_token|client_secret|password|api_key)(?:\"|')?\s*:\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
    ),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
]


def redact_sensitive_text(value: str) -> str:
    text = str(value or "")
    redacted = text
    redacted = SENSITIVE_TEXT_PATTERNS[0].sub(r"\1 [redacted]", redacted)
    for pattern in SENSITIVE_TEXT_PATTERNS[1:-1]:
        redacted = pattern.sub(r"\1[redacted]", redacted)
    redacted = SENSITIVE_TEXT_PATTERNS[-1].sub("[redacted-email]", redacted)
    return redacted


def truncate_monitoring_value(value: str, max_chars: int = 1200) -> str:
    text = redact_sensitive_text(value)
    return text[:max_chars] + ("...[truncated]" if len(text) > max_chars else "")


def safe_monitoring_value(key_text: str, value: Any) -> Any:
    if any(term in key_text.lower() for term in SENSITIVE_METADATA_KEY_TERMS):
        return "[redacted]"
    if isinstance(value, str):
        return truncate_monitoring_value(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {
            str(child_key): safe_monitoring_value(str(child_key), child_value)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [safe_monitoring_value(key_text, item) for item in value][:50]
    serialized = json.dumps(value, ensure_ascii=False, default=str)
    return truncate_monitoring_value(serialized)


def safe_monitoring_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        key_text = str(key)
        safe[key_text] = safe_monitoring_value(key_text, value)
    return safe


def write_monitoring_event(
    category: str,
    event_name: str,
    severity: str = "warning",
    request: Optional[Request] = None,
    user_id: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    if not monitoring_enabled():
        return
    try:
        request_path = request.url.path if request else ""
        request_method = request.method if request else ""
        client_ip = get_client_ip(request) if request else ""
        user_agent = request.headers.get("user-agent", "")[:400] if request else ""
        safe_metadata = safe_monitoring_metadata(metadata)
        with get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO monitoring_events (
                    event_id, category, event_name, severity, user_id, request_path,
                    request_method, client_ip, user_agent, created_at, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    secrets.token_hex(12),
                    category,
                    event_name,
                    severity,
                    user_id,
                    request_path,
                    request_method,
                    client_ip,
                    user_agent,
                    datetime.now().isoformat(),
                    json.dumps(safe_metadata, ensure_ascii=False),
                ),
            )
        if severity in MONITORING_ALERT_SEVERITIES or category in MONITORING_ALERT_CATEGORIES:
            logger.warning("Monitoring event [%s/%s/%s]: %s", severity, category, event_name, safe_metadata)
    except Exception as exc:
        logger.warning("Failed to write monitoring event: %s", exc)


def classify_error_detail(detail: Any) -> str:
    text = str(detail or "").lower()
    if "google" in text or "microsoft" in text or "oauth" in text or "token" in text or "scope" in text:
        return "oauth"
    if "openai" in text or "api key" in text:
        return "server_error"
    if "twilio" in text or "sms" in text or "email sending" in text or "send" in text:
        return "report_delivery"
    if "delete" in text or "purge" in text:
        return "retention"
    return "server_error"


def find_rate_limit_rule(method: str, path: str) -> Optional[tuple[str, str, int, int]]:
    for rule_method, rule_path, max_requests, window_seconds in RATE_LIMIT_RULES:
        if method.upper() != rule_method:
            continue
        if path == rule_path or path.startswith(f"{rule_path}/"):
            return (rule_method, rule_path, max_requests, window_seconds)
    if method.upper() == "POST" and path.endswith("/send-email"):
        return ("POST", "*/send-email", 20, 3600)
    return None


def is_rate_limit_enabled() -> bool:
    return os.getenv("EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED", "true").lower() != "false"


def add_security_headers(response: Response) -> None:
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if is_production_environment():
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


@app.middleware("http")
async def security_and_limits_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                write_monitoring_event(
                    "security",
                    "request_too_large",
                    "warning",
                    request=request,
                    metadata={"content_length": content_length, "limit": MAX_REQUEST_BODY_BYTES},
                )
                response = JSONResponse({"detail": "Request is too large."}, status_code=413)
                add_security_headers(response)
                return response
        except ValueError:
            write_monitoring_event(
                "security",
                "invalid_content_length",
                "warning",
                request=request,
                metadata={"content_length": content_length},
            )
            response = JSONResponse({"detail": "Invalid Content-Length header."}, status_code=400)
            add_security_headers(response)
            return response

    if not is_rate_limit_enabled():
        try:
            response = await call_next(request)
        except HTTPException as exc:
            if exc.status_code >= 500:
                write_monitoring_event(
                    classify_error_detail(exc.detail),
                    "http_exception",
                    "error",
                    request=request,
                    metadata={"status_code": exc.status_code, "detail": exc.detail},
                )
            raise
        except Exception as exc:
            write_monitoring_event(
                "server_error",
                "unhandled_exception",
                "critical",
                request=request,
                metadata={"error": str(exc), "error_type": exc.__class__.__name__},
            )
            raise
        add_security_headers(response)
        return response

    rule = find_rate_limit_rule(request.method, request.url.path)
    if not rule:
        try:
            response = await call_next(request)
        except HTTPException as exc:
            if exc.status_code >= 500:
                write_monitoring_event(
                    classify_error_detail(exc.detail),
                    "http_exception",
                    "error",
                    request=request,
                    metadata={"status_code": exc.status_code, "detail": exc.detail},
                )
            raise
        except Exception as exc:
            write_monitoring_event(
                "server_error",
                "unhandled_exception",
                "critical",
                request=request,
                metadata={"error": str(exc), "error_type": exc.__class__.__name__},
            )
            raise
        add_security_headers(response)
        return response

    _, rule_path, max_requests, window_seconds = rule
    now = time.time()
    bucket_key = f"{get_client_ip(request)}:{request.method.upper()}:{rule_path}"
    with RATE_LIMIT_LOCK:
        recent = [timestamp for timestamp in RATE_LIMIT_BUCKETS.get(bucket_key, []) if now - timestamp < window_seconds]
        if len(recent) >= max_requests:
            retry_after = max(1, int(window_seconds - (now - recent[0])))
            write_monitoring_event(
                "abuse",
                "rate_limit_hit",
                "warning",
                request=request,
                metadata={"rule": rule_path, "max_requests": max_requests, "window_seconds": window_seconds, "retry_after": retry_after},
            )
            response = JSONResponse(
                {"detail": "Too many requests. Please wait and try again."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
            add_security_headers(response)
            return response
        recent.append(now)
        RATE_LIMIT_BUCKETS[bucket_key] = recent

    try:
        response = await call_next(request)
    except HTTPException as exc:
        if exc.status_code >= 500:
            write_monitoring_event(
                classify_error_detail(exc.detail),
                "http_exception",
                "error",
                request=request,
                metadata={"status_code": exc.status_code, "detail": exc.detail},
            )
        raise
    except Exception as exc:
        write_monitoring_event(
            "server_error",
            "unhandled_exception",
            "critical",
            request=request,
            metadata={"error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise
    add_security_headers(response)
    return response

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "dashboard_static"
APP_STORAGE_DIR = Path(os.getenv("EMAIL_SUMMARIZER_STORAGE_DIR", str(BASE_DIR / "data"))).resolve()
OUTPUT_ROOT_DIR = Path(os.getenv("EMAIL_SUMMARIZER_OUTPUT_DIR", str(BASE_DIR / "email_summaries_output"))).resolve()
DATA_DIR = APP_STORAGE_DIR / "users"
APP_DATA_DIR = APP_STORAGE_DIR / "app"
DB_PATH = APP_DATA_DIR / "app.db"
PUBLIC_REPORTS_DIR = APP_STORAGE_DIR / "public_reports"
SESSION_COOKIE_NAME = "email_dashboard_session"
SESSION_COOKIE_MAX_AGE_SECONDS = int(os.getenv("EMAIL_SUMMARIZER_SESSION_COOKIE_MAX_AGE_SECONDS", str(60 * 60 * 24 * 7)))
READ_RETENTION_DAYS = 20
SUBSCRIPTION_TRIAL_DAYS = int(os.getenv("EMAIL_SUMMARIZER_SUBSCRIPTION_TRIAL_DAYS", "7"))
SUBSCRIPTION_PRICE_CENTS = int(os.getenv("EMAIL_SUMMARIZER_SUBSCRIPTION_PRICE_CENTS", "499"))
SUBSCRIPTION_PRICE_LABEL = os.getenv("EMAIL_SUMMARIZER_SUBSCRIPTION_PRICE_LABEL", "$4.99").strip() or "$4.99"
SUBSCRIPTION_PLAN_NAME = os.getenv("EMAIL_SUMMARIZER_SUBSCRIPTION_PLAN_NAME", "Discere Member").strip() or "Discere Member"
DEFAULT_BILLING_EXEMPT_EMAILS = {
    "bnzhang2001@gmail.com",
    "bnnzhang2001@outlook.com",
    "peter@yj-semitech.com",
}
REPORT_EMAIL_MODE_FULL = "full_report"
REPORT_EMAIL_MODE_PRIVATE = "private_notification"
REPORT_EMAIL_MODES = {REPORT_EMAIL_MODE_FULL, REPORT_EMAIL_MODE_PRIVATE}
MANUAL_REPORT_EMAIL_SUBJECT = "Discere - Email Summary"
SCHEDULED_REPORT_EMAIL_FALLBACK_SUBJECT = "Discere - Scheduled Email Summary"
DEFAULT_BACKGROUND_THEME = "default"
BACKGROUND_THEMES = {
    "default",
    "white",
    "blue",
    "pink",
    "red",
    "stone",
    "mist",
    "green",
    "purple",
    "ocean",
    "rose",
    "amber",
    "slate",
}
GOOGLE_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
GOOGLE_OAUTH_STATE_COOKIE = "email_dashboard_google_state"
GOOGLE_OAUTH_NEXT_COOKIE = "email_dashboard_google_next"
GOOGLE_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
]
REQUIRED_GOOGLE_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
REQUIRED_MICROSOFT_MAIL_SCOPE = "https://graph.microsoft.com/Mail.Read"
TERMS_VERSION = "2026-05-06"
PRIVACY_VERSION = "2026-05-06"
MICROSOFT_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
MICROSOFT_OAUTH_STATE_COOKIE = "email_dashboard_microsoft_state"
MICROSOFT_OAUTH_NEXT_COOKIE = "email_dashboard_microsoft_next"
MICROSOFT_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "offline_access",
    REQUIRED_MICROSOFT_MAIL_SCOPE,
]
MICROSOFT_MAILBOX_TOKEN_SCOPES = [
    REQUIRED_MICROSOFT_MAIL_SCOPE,
    "offline_access",
]
MICROSOFT_RECONNECT_MESSAGE = (
    "Microsoft mailbox access expired or needs permission again. "
    "Reconnect Microsoft and approve mailbox access. If this keeps happening, the Microsoft account may need admin approval."
)
VIP_263_IMAP_SERVER = "imap.263.net"
VIP_263_IMAP_PORT = "993"
VIP_263_SMTP_HOST = "smtp.263.net"
VIP_263_SMTP_PORT = "465"
VIP_263_IMAP_FOLDER = "INBOX"
GENERIC_SUMMARIZER_ERROR_MESSAGE = (
    "Discere could not finish the email check. Please try again. "
    "If it keeps happening, contact Discere support."
)
REQUIRED_PRODUCTION_ENV_VARS = [
    "EMAIL_SUMMARIZER_PUBLIC_BASE_URL",
    "OPENAI_API_KEY",
    "EMAIL_SUMMARIZER_ENCRYPTION_KEY",
]
RECOMMENDED_PRODUCTION_ENV_VARS = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "MICROSOFT_CLIENT_ID",
    "MICROSOFT_CLIENT_SECRET",
    "EMAIL_SUMMARIZER_REPORT_SMTP_USER",
    "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD",
]
ACCOUNT_SCOPED_SETTING_KEYS = {
    "WHITELIST_SENDERS",
    "CONTACT_PROFILES",
    "IMAP_USER",
    "IMAP_PASSWORD",
    "IMAP_SERVER",
    "IMAP_PORT",
    "IMAP_FOLDER",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_HOST",
    "SMTP_PORT",
    "SUMMARY_RECIPIENT",
    "MAILBOX_CONNECTION_CONFIRMED",
    "FIRST_NAME",
    "LAST_NAME",
    "REPORT_EMAIL_MODE",
    "SUBSCRIPTION_STATUS",
    "SUBSCRIPTION_TRIAL_STARTED_AT",
    "SUBSCRIPTION_TRIAL_ENDS_AT",
    "SUBSCRIPTION_ACTIVATED_AT",
    "STRIPE_CUSTOMER_ID",
    "STRIPE_SUBSCRIPTION_ID",
}
USAGE_LIMIT_ENV_KEYS = {
    "run_summarizer": ("EMAIL_SUMMARIZER_LIMIT_RUN_SUMMARIZER_PER_DAY", 10),
    "scheduled_report": ("EMAIL_SUMMARIZER_LIMIT_SCHEDULED_REPORTS_PER_DAY", 24),
    "chat": ("EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY", 100),
    "refine": ("EMAIL_SUMMARIZER_LIMIT_REFINE_PER_DAY", 30),
    "report_delivery": ("EMAIL_SUMMARIZER_LIMIT_REPORT_DELIVERY_PER_DAY", 50),
}

app.mount("/dashboard_static", StaticFiles(directory=STATIC_DIR), name="dashboard_static")


def get_db_connection() -> sqlite3.Connection:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def track_analytics_event(user_id: str, event_name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    safe_metadata = safe_monitoring_metadata(metadata)
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
                json.dumps(safe_metadata, ensure_ascii=False),
            ),
        )


def sanitize_metadata_json_text(raw_value: Any) -> str:
    try:
        parsed = json.loads(str(raw_value or "{}"))
    except json.JSONDecodeError:
        return truncate_monitoring_value(str(raw_value or ""))
    return json.dumps(safe_monitoring_metadata(parsed if isinstance(parsed, dict) else {"value": parsed}), ensure_ascii=False)


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
                days_back INTEGER NOT NULL DEFAULT 1,
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

            CREATE TABLE IF NOT EXISTS usage_counters (
                user_id TEXT NOT NULL,
                usage_key TEXT NOT NULL,
                window_start TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(user_id, usage_key, window_start),
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS monitoring_events (
                event_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                event_name TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning',
                user_id TEXT,
                request_path TEXT,
                request_method TEXT,
                client_ip TEXT,
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


def validate_startup_configuration() -> None:
    readiness = build_deploy_readiness()
    messages = readiness.get("errors", []) + readiness.get("warnings", [])
    for message in messages:
        logger.warning("Deploy readiness: %s", message)
    if readiness.get("errors") and os.getenv("EMAIL_SUMMARIZER_STRICT_STARTUP_VALIDATION", "false").lower() == "true":
        raise RuntimeError("Production readiness checks failed: " + "; ".join(readiness["errors"]))


def enforce_text_limit(value: str, label: str, max_chars: int) -> str:
    text = str(value or "").strip()
    if len(text) > max_chars:
        raise HTTPException(status_code=413, detail=f"{label} is too long. Limit: {max_chars} characters.")
    return text


def enforce_summary_id_limit(summary_ids: List[str]) -> None:
    if len(summary_ids) > MAX_SUMMARY_IDS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Too many summaries selected. Limit: {MAX_SUMMARY_IDS_PER_REQUEST}.",
        )


def get_usage_window_start() -> str:
    return datetime.now(ZoneInfo("UTC")).date().isoformat()


def get_usage_limit(usage_key: str) -> int:
    env_key, default = USAGE_LIMIT_ENV_KEYS.get(usage_key, ("", 0))
    raw_value = os.getenv(env_key, str(default)).strip() if env_key else str(default)
    try:
        return max(0, int(raw_value))
    except ValueError:
        return default


def get_usage_snapshot(user_id: str) -> Dict[str, Any]:
    window_start = get_usage_window_start()
    usage: Dict[str, Dict[str, int]] = {}
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT usage_key, count
            FROM usage_counters
            WHERE user_id = ? AND window_start = ?
            """,
            (user_id, window_start),
        ).fetchall()
    for usage_key, (_, default_limit) in USAGE_LIMIT_ENV_KEYS.items():
        usage[usage_key] = {"count": 0, "limit": get_usage_limit(usage_key)}
    for row in rows:
        usage_key = str(row["usage_key"])
        usage.setdefault(usage_key, {"count": 0, "limit": get_usage_limit(usage_key)})
        usage[usage_key]["count"] = int(row["count"] or 0)
    return {"user_id": user_id, "window_start": window_start, "usage": usage}


def enforce_usage_limit(user_id: str, usage_key: str, amount: int = 1) -> Dict[str, int]:
    limit = get_usage_limit(usage_key)
    if limit <= 0:
        return {"count": 0, "limit": limit, "remaining": -1}

    window_start = get_usage_window_start()
    now = datetime.now().isoformat()
    limit_hit: Optional[Dict[str, int]] = None
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO usage_counters (user_id, usage_key, window_start, count, updated_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (user_id, usage_key, window_start, now),
        )
        row = connection.execute(
            """
            SELECT count
            FROM usage_counters
            WHERE user_id = ? AND usage_key = ? AND window_start = ?
            """,
            (user_id, usage_key, window_start),
        ).fetchone()
        current_count = int((row or {})["count"] or 0)
        if current_count + amount > limit:
            limit_hit = {"count": current_count, "limit": limit}
        else:
            new_count = current_count + amount
            connection.execute(
                """
                UPDATE usage_counters
                SET count = ?, updated_at = ?
                WHERE user_id = ? AND usage_key = ? AND window_start = ?
                """,
                (new_count, now, user_id, usage_key, window_start),
            )
            return {"count": new_count, "limit": limit, "remaining": max(0, limit - new_count)}

    if limit_hit:
        track_analytics_event(
            user_id,
            "usage_limit_hit",
            {"usage_key": usage_key, "count": limit_hit["count"], "limit": limit_hit["limit"]},
        )
        raise HTTPException(
            status_code=429,
            detail=f"Daily usage limit reached for {usage_key.replace('_', ' ')}. Limit: {limit}/day.",
        )

    return {"count": 0, "limit": limit, "remaining": limit}


def reconnect_error(provider: str, purpose: str, detail: str, reconnect_url: str = "") -> HTTPException:
    headers = {
        "X-Discere-Reconnect-Provider": provider,
        "X-Discere-Reconnect-Purpose": purpose,
    }
    if reconnect_url:
        headers["X-Discere-Reconnect-Url"] = reconnect_url
    return HTTPException(
        status_code=400,
        detail=detail,
        headers=headers,
    )


class RunSummarizerRequest(BaseModel):
    user_id: Optional[str] = None
    days_back: int = 1


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
    conversation: List[Dict[str, str]] = []


class PublicChatRequest(BaseModel):
    question: str
    conversation: List[Dict[str, str]] = []


class CombinedSummaryRequest(BaseModel):
    user_id: Optional[str] = None
    summary_ids: List[str]


class RefineSummaryRequest(BaseModel):
    user_id: Optional[str] = None
    title: str = ""
    markdown: str
    instructions: str
    save_preference: bool = False


class RefineSelectedSummariesRequest(BaseModel):
    user_id: Optional[str] = None
    summary_ids: List[str]
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
    manual_access_password: str = ""
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
    report_email_mode: str = ""
    background_theme: str = ""
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


class VipMailboxPasswordRequest(BaseModel):
    mailbox_password: str


class ReportScheduleRequest(BaseModel):
    user_id: Optional[str] = None
    name: str = "Scheduled Report"
    active: bool = True
    interval_value: int = 1
    interval_unit: str = "days"
    days_back: int = 1
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


class UiHintSeenRequest(BaseModel):
    user_id: Optional[str] = None
    hint_key: str


def safe_next_path(next_url: str = "/dashboard") -> str:
    candidate = str(next_url or "").strip()
    if not candidate:
        return "/dashboard"
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/dashboard"
    if "\\" in candidate:
        return "/dashboard"
    return candidate


@app.get("/")
def home() -> Response:
    return FileResponse(STATIC_DIR / "home.html")


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


def check_path_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        check_file = path / ".write-check"
        check_file.write_text(datetime.now().isoformat(), encoding="utf-8")
        check_file.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def build_deploy_readiness() -> Dict[str, Any]:
    report_sender = get_report_sender_config()
    checks = {
        "production_environment": is_production_environment(),
        "public_base_url_configured": bool(PUBLIC_BASE_URL),
        "public_base_url_https": PUBLIC_BASE_URL.startswith("https://"),
        "cookie_secure": SESSION_COOKIE_SECURE,
        "storage_dir_writable": check_path_writable(APP_STORAGE_DIR),
        "output_dir_writable": check_path_writable(OUTPUT_ROOT_DIR),
        "database_reachable": False,
        "openai_api_key_configured": bool(get_app_config_value("OPENAI_API_KEY")),
        "encryption_key_configured": bool(get_app_config_value("EMAIL_SUMMARIZER_ENCRYPTION_KEY")),
        "google_oauth_configured": bool(get_app_config_value("GOOGLE_CLIENT_ID") and get_app_config_value("GOOGLE_CLIENT_SECRET")),
        "microsoft_oauth_configured": bool(get_app_config_value("MICROSOFT_CLIENT_ID") and get_app_config_value("MICROSOFT_CLIENT_SECRET")),
        "google_redirect_configured_or_derivable": bool(get_app_config_value("GOOGLE_REDIRECT_URI") or PUBLIC_BASE_URL),
        "microsoft_redirect_configured_or_derivable": bool(get_app_config_value("MICROSOFT_REDIRECT_URI") or PUBLIC_BASE_URL),
        "discere_report_sender_configured": bool(report_sender["host"] and report_sender["user"] and report_sender["password"]),
        "manual_mailbox_allowlist_configured": bool(configured_manual_mailbox_allowed_emails()),
        "manual_signup_access_password_custom": bool(os.getenv("EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD", "").strip()),
        "vip_mailbox_email_configured": bool(configured_vip_mailbox_email()),
        "vip_mailbox_email_allowlisted": bool(email_is_manual_mailbox_allowed(configured_vip_mailbox_email())),
        "rate_limit_enabled": is_rate_limit_enabled(),
        "cors_origins_production_safe": cors_origins_are_production_safe(),
        "security_headers_enabled": True,
        "request_size_limit_bytes": MAX_REQUEST_BODY_BYTES,
        "usage_limits_enabled": True,
        "monitoring_enabled": monitoring_enabled(),
        "recent_monitoring_alerts": 0,
    }
    try:
        with get_db_connection() as connection:
            connection.execute("SELECT 1").fetchone()
            since = (datetime.now() - timedelta(hours=24)).isoformat()
            checks["recent_monitoring_alerts"] = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM monitoring_events
                WHERE created_at >= ?
                  AND (severity IN ('error', 'critical')
                    OR category IN ('oauth', 'summarizer', 'data_isolation', 'report_delivery', 'abuse', 'server_error', 'security', 'retention'))
                """,
                (since,),
            ).fetchone()["count"]
        checks["database_reachable"] = True
    except sqlite3.Error:
        checks["database_reachable"] = False

    errors: List[str] = []
    warnings: List[str] = []
    if checks["production_environment"]:
        for key in REQUIRED_PRODUCTION_ENV_VARS:
            if not get_app_config_value(key):
                errors.append(f"Missing required production env var: {key}")
        for key in RECOMMENDED_PRODUCTION_ENV_VARS:
            if not get_app_config_value(key):
                warnings.append(f"Missing recommended production env var: {key}")
        if not checks["cookie_secure"]:
            errors.append("Production session cookies must use Secure=true.")
        if PUBLIC_BASE_URL and not checks["public_base_url_https"]:
            errors.append("Production public base URL should use HTTPS.")
        if not checks["cors_origins_production_safe"]:
            errors.append("Production CORS origins must include at least one HTTPS public origin and cannot include '*'.")
        if os.getenv("RENDER") and not path_is_under(APP_STORAGE_DIR, Path("/var/data")):
            errors.append("Production storage directory should be on the Render persistent disk.")
        if os.getenv("RENDER") and not path_is_under(OUTPUT_ROOT_DIR, Path("/var/data")):
            errors.append("Production output directory should be on the Render persistent disk.")

    if not checks["storage_dir_writable"]:
        errors.append("Storage directory is not writable.")
    if not checks["output_dir_writable"]:
        errors.append("Output directory is not writable.")
    if not checks["database_reachable"]:
        errors.append("SQLite database is not reachable.")
    if not checks["monitoring_enabled"]:
        warnings.append("Production monitoring is disabled.")
    if int(checks["recent_monitoring_alerts"] or 0) > 0:
        warnings.append(f"Recent monitoring alerts in the last 24 hours: {checks['recent_monitoring_alerts']}.")
    if not checks["google_redirect_configured_or_derivable"]:
        warnings.append("Google OAuth redirect URL is not configured or derivable.")
    if not checks["microsoft_redirect_configured_or_derivable"]:
        warnings.append("Microsoft OAuth redirect URL is not configured or derivable.")
    if checks["manual_mailbox_allowlist_configured"] and not checks["manual_signup_access_password_custom"]:
        errors.append("Manual mailbox allowlist is configured; set EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD to a private value.")
    if checks["manual_mailbox_allowlist_configured"] and not checks["vip_mailbox_email_configured"]:
        errors.append("Manual mailbox allowlist is configured; set EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL.")
    if checks["vip_mailbox_email_configured"] and not checks["vip_mailbox_email_allowlisted"]:
        errors.append("EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL must also be listed in EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS.")

    return {
        "status": "ready" if not errors else "needs_attention",
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
    }


@app.get("/health/deployment")
def deployment_health(request: Request) -> Dict[str, Any]:
    require_admin(request)
    readiness = build_deploy_readiness()
    return {
        "status": "ok",
        **readiness,
        "storage_dir": str(APP_STORAGE_DIR),
        "output_dir": str(OUTPUT_ROOT_DIR),
        "cors_origins": APP_CORS_ORIGINS,
    }


@app.get("/health/readiness")
def readiness_health() -> Dict[str, Any]:
    readiness = build_deploy_readiness()
    return {
        "status": readiness["status"],
        "ready": readiness["status"] == "ready",
    }


@app.get("/admin/analytics")
def admin_analytics(request: Request, limit: int = Query(100, ge=1, le=1000)) -> Dict[str, Any]:
    require_admin(request)
    with get_db_connection() as connection:
        totals = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event_name, COUNT(*) AS count
                FROM analytics_events
                GROUP BY event_name
                ORDER BY count DESC, event_name
                """
            ).fetchall()
        ]
        recent_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event_id, user_id, event_name, created_at, metadata_json
                FROM analytics_events
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
    for event in recent_events:
        event["metadata_json"] = sanitize_metadata_json_text(event.get("metadata_json"))
    return {"totals": totals, "events": recent_events}


@app.get("/admin/bug-reports")
def admin_bug_reports(request: Request, limit: int = Query(100, ge=1, le=1000)) -> Dict[str, Any]:
    require_admin(request)
    with get_db_connection() as connection:
        reports = [
            dict(row)
            for row in connection.execute(
                """
                SELECT bug_id, user_id, email, title, description, page_url, user_agent, created_at, metadata_json
                FROM bug_reports
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
    return {"count": len(reports), "bug_reports": reports}


@app.get("/admin/monitoring")
def admin_monitoring(request: Request, limit: int = Query(100, ge=1, le=1000)) -> Dict[str, Any]:
    require_admin(request)
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    with get_db_connection() as connection:
        totals = [
            dict(row)
            for row in connection.execute(
                """
                SELECT severity, category, COUNT(*) AS count
                FROM monitoring_events
                WHERE created_at >= ?
                GROUP BY severity, category
                ORDER BY count DESC, severity, category
                """,
                (since,),
            ).fetchall()
        ]
        recent_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event_id, category, event_name, severity, user_id, request_path,
                       request_method, client_ip, user_agent, created_at, metadata_json
                FROM monitoring_events
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
    for event in recent_events:
        event["metadata_json"] = sanitize_metadata_json_text(event.get("metadata_json"))
    return {
        "enabled": monitoring_enabled(),
        "window_hours": 24,
        "totals": totals,
        "events": recent_events,
    }


@app.get("/usage")
def current_usage(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    return get_usage_snapshot(resolved_user_id)


@app.get("/billing/status")
def billing_status(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    return {"user_id": resolved_user_id, "subscription": subscription_status_for_profile(profile, persist=True)}


@app.post("/billing/checkout")
def billing_checkout(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    subscription = subscription_status_for_profile(profile, persist=True)
    if subscription.get("is_exempt"):
        return {
            "success": True,
            "checkout_configured": False,
            "checkout_url": "",
            "message": "No billing is required for this testing account.",
            "subscription": subscription,
        }
    if not subscription.get("requires_subscription") and subscription.get("status") == "member":
        portal_url = os.getenv("EMAIL_SUMMARIZER_STRIPE_CUSTOMER_PORTAL_URL", "").strip()
        return {
            "success": bool(portal_url),
            "checkout_configured": bool(portal_url),
            "checkout_url": portal_url,
            "message": "Opening subscription management." if portal_url else "Subscription management is not connected yet.",
            "subscription": subscription,
        }

    checkout_url = os.getenv("EMAIL_SUMMARIZER_STRIPE_CHECKOUT_URL", "").strip()
    if checkout_url:
        return {
            "success": True,
            "checkout_configured": True,
            "checkout_url": checkout_url,
            "message": "Opening secure checkout.",
            "subscription": subscription,
        }
    return {
        "success": False,
        "checkout_configured": False,
        "checkout_url": "",
        "message": "Stripe checkout is not connected yet. Add Stripe checkout settings before accepting paid subscriptions.",
        "subscription": subscription,
    }


@app.on_event("startup")
def startup_configuration_check() -> None:
    validate_startup_configuration()


@app.get("/login")
def login_page(request: Request) -> Response:
    next_url = safe_next_path(str(request.query_params.get("next", "/dashboard")))
    if get_session_user_id(request):
        return RedirectResponse(next_url)
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/dashboard")
def dashboard(request: Request) -> Response:
    if not get_session_user_id(request):
        return RedirectResponse(f"/login?next={quote('/dashboard', safe='')}")
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
def signup_page() -> RedirectResponse:
    return RedirectResponse("/login")


@app.get("/manual-signup")
def manual_signup_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "signup.html")


@app.get("/manual-login")
def manual_login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/privacy")
def privacy_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "privacy.html")


@app.get("/security")
def security_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "security.html")


@app.get("/how-to")
def how_to_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "how_to.html")


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
    validate_manual_signup_access(email, request.manual_access_password)
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

    settings = apply_vip_manual_mailbox_preconfiguration(settings, email)
    settings["SUMMARY_RECIPIENT"] = settings.get("SUMMARY_RECIPIENT") or email
    settings["MAILBOX_CONNECTION_CONFIRMED"] = (
        "true"
        if str(settings.get("MAILBOX_CONNECTION_CONFIRMED", "")).strip().lower() == "true"
        and str(settings.get("IMAP_PASSWORD", "")).strip()
        else "false"
    )
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
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    microsoft_connected = bool((profile.get("microsoft_oauth") or {}).get("refresh_token") or (profile.get("microsoft_oauth") or {}).get("access_token"))
    if not google_connected and not microsoft_connected and not profile_manual_mailbox_allowed(profile):
        write_monitoring_event(
            "security",
            "manual_login_email_not_allowlisted",
            "warning",
            user_id=str(profile.get("user_id", "")),
            metadata={"email": profile.get("email", "")},
        )
        raise HTTPException(status_code=403, detail="This account must use Google or Microsoft sign-in.")

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
        connection.execute("DELETE FROM report_schedules WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM analytics_events WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM bug_reports WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM usage_counters WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    user_data_dir = DATA_DIR / user_id
    user_output_dir = OUTPUT_ROOT_DIR / user_id
    user_public_report_dir = PUBLIC_REPORTS_DIR / user_id
    if user_data_dir.exists():
        shutil.rmtree(user_data_dir, ignore_errors=True)
    if user_output_dir.exists():
        shutil.rmtree(user_output_dir, ignore_errors=True)
    if user_public_report_dir.exists():
        shutil.rmtree(user_public_report_dir, ignore_errors=True)

    clear_session(response, request)
    return {"success": True, "user_id": profile["user_id"], "email": profile.get("email", "")}


@app.get("/auth/google/start")
def auth_google_start(
    next: str = "/dashboard",
    login_hint: str = "",
    prompt: str = "consent",
) -> RedirectResponse:
    try:
        config = get_google_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?google_error=not_configured")
    scope = " ".join(GOOGLE_OAUTH_SCOPES)
    login_hint_value = login_hint.strip()
    prompt_value = prompt.strip()
    next = safe_next_path(next)
    state = secrets.token_urlsafe(24)
    GOOGLE_OAUTH_STATE[state] = {"next": next, "prompt": prompt_value}
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
        write_monitoring_event("oauth", "google_callback_error", "error", request=request, metadata={"error": error})
        return RedirectResponse(f"/dashboard?google_error={quote(error, safe='')}")
    cookie_state = request.cookies.get(GOOGLE_OAUTH_STATE_COOKIE)
    known_state = GOOGLE_OAUTH_STATE.get(state or "")
    if not code or not state:
        write_monitoring_event("oauth", "google_invalid_callback", "error", request=request, metadata={"reason": "missing_code_or_state"})
        return RedirectResponse("/dashboard?google_error=invalid_callback")
    if cookie_state and state == cookie_state:
        pass
    elif known_state:
        pass
    else:
        write_monitoring_event("oauth", "google_invalid_callback", "error", request=request, metadata={"reason": "state_mismatch"})
        return RedirectResponse("/dashboard?google_error=invalid_callback")

    config = get_google_oauth_config()
    state_metadata = GOOGLE_OAUTH_STATE.pop(state, {}) if state else {}
    next_url = safe_next_path(request.cookies.get(GOOGLE_OAUTH_NEXT_COOKIE) or state_metadata.get("next") or "/dashboard")

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
        write_monitoring_event("oauth", "google_token_exchange_failed", "error", request=request)
        response = RedirectResponse("/dashboard?google_error=token_exchange_failed")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    access_token = token_payload.get("access_token")
    if not access_token:
        write_monitoring_event("oauth", "google_missing_access_token", "error", request=request)
        response = RedirectResponse("/dashboard?google_error=missing_access_token")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    try:
        userinfo = get_json_with_bearer(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            access_token,
            error_prefix="Google Gmail profile request failed",
        )
    except HTTPException:
        write_monitoring_event("oauth", "google_gmail_profile_failed", "error", request=request)
        response = RedirectResponse("/dashboard?google_error=gmail_profile_failed")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    email = str(userinfo.get("emailAddress") or userinfo.get("email") or "").strip().lower()
    display_name = ""
    if not email:
        write_monitoring_event("oauth", "google_no_email_returned", "error", request=request)
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

    existing_google_oauth = profile.get("google_oauth") or {}
    google_refresh_token = str(token_payload.get("refresh_token", "") or existing_google_oauth.get("refresh_token", "") or "").strip()
    if not google_refresh_token:
        write_monitoring_event("oauth", "google_missing_refresh_token_after_login", "error", request=request, user_id=str(profile.get("user_id", "")))
        if state_metadata.get("prompt") == "consent":
            response = RedirectResponse("/dashboard?google_error=missing_refresh_token")
            response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
            response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
            return response
        reconnect_query = urlencode({"next": next_url, "login_hint": email, "prompt": "consent"})
        response = RedirectResponse(f"/auth/google/start?{reconnect_query}")
        response.delete_cookie(GOOGLE_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(GOOGLE_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    profile["google_oauth"] = {
        "provider": "google",
        "email": email,
        "access_token": token_payload.get("access_token", ""),
        "refresh_token": google_refresh_token,
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
    request: Request,
    next: str = "/dashboard",
    login_hint: str = "",
    prompt: str = "consent",
    force_reconsent: bool = False,
) -> RedirectResponse:
    try:
        config = get_microsoft_oauth_config()
    except HTTPException:
        return RedirectResponse("/dashboard?microsoft_error=not_configured")

    scope = " ".join(MICROSOFT_OAUTH_SCOPES)
    login_hint_value = login_hint.strip()
    prompt_value = prompt.strip()
    next = safe_next_path(next)
    if force_reconsent:
        prompt_value = "consent"
        session_user_id = get_session_user_id(request)
        if session_user_id:
            profile = load_profile(session_user_id)
            if profile:
                profile["microsoft_oauth"] = {}
                profile["settings"] = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
                profile["settings"]["MAILBOX_CONNECTION_CONFIRMED"] = "false"
                save_profile(profile)
    state = secrets.token_urlsafe(24)
    MICROSOFT_OAUTH_STATE[state] = {"next": next, "prompt": prompt_value}
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
        write_monitoring_event("oauth", "microsoft_callback_error", "error", request=request, metadata={"error": error})
        return RedirectResponse(f"/dashboard?microsoft_error={quote(error, safe='')}")

    cookie_state = request.cookies.get(MICROSOFT_OAUTH_STATE_COOKIE)
    known_state = MICROSOFT_OAUTH_STATE.get(state or "")
    if not code or not state:
        write_monitoring_event("oauth", "microsoft_invalid_callback", "error", request=request, metadata={"reason": "missing_code_or_state"})
        return RedirectResponse("/dashboard?microsoft_error=invalid_callback")
    if cookie_state and state == cookie_state:
        pass
    elif known_state:
        pass
    else:
        write_monitoring_event("oauth", "microsoft_invalid_callback", "error", request=request, metadata={"reason": "state_mismatch"})
        return RedirectResponse("/dashboard?microsoft_error=invalid_callback")

    config = get_microsoft_oauth_config()
    state_metadata = MICROSOFT_OAUTH_STATE.pop(state, {}) if state else {}
    next_url = safe_next_path(request.cookies.get(MICROSOFT_OAUTH_NEXT_COOKIE) or state_metadata.get("next") or "/dashboard")
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
        write_monitoring_event("oauth", "microsoft_token_exchange_failed", "error", request=request)
        response = RedirectResponse("/dashboard?microsoft_error=token_exchange_failed")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    access_token = token_payload.get("access_token")
    if not access_token:
        write_monitoring_event("oauth", "microsoft_missing_access_token", "error", request=request)
        response = RedirectResponse("/dashboard?microsoft_error=missing_access_token")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response

    claims = decode_jwt_payload(str(token_payload.get("id_token", "")))
    userinfo = {
        "mail": str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "").strip(),
        "userPrincipalName": str(claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "").strip(),
        "displayName": str(claims.get("name") or "").strip(),
    }
    fallback_email = str(userinfo.get("mail") or userinfo.get("userPrincipalName") or "").strip().lower()
    display_name = ""
    email = resolve_microsoft_account_email(userinfo, token_payload) or fallback_email
    if not email:
        write_monitoring_event("oauth", "microsoft_no_email_returned", "error", request=request)
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

    existing_microsoft_oauth = profile.get("microsoft_oauth") or {}
    microsoft_refresh_token = str(token_payload.get("refresh_token", "") or existing_microsoft_oauth.get("refresh_token", "") or "").strip()
    if not microsoft_refresh_token:
        write_monitoring_event("oauth", "microsoft_missing_refresh_token_after_login", "error", request=request, user_id=str(profile.get("user_id", "")))
        if state_metadata.get("prompt") == "consent":
            response = RedirectResponse("/dashboard?microsoft_error=missing_refresh_token")
            response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
            response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
            return response
        reconnect_query = urlencode({"next": next_url, "login_hint": email, "prompt": "consent"})
        response = RedirectResponse(f"/auth/microsoft/start?{reconnect_query}")
        response.delete_cookie(MICROSOFT_OAUTH_STATE_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        response.delete_cookie(MICROSOFT_OAUTH_NEXT_COOKIE, domain=SESSION_COOKIE_DOMAIN, path="/")
        return response
    profile["microsoft_oauth"] = {
        "provider": "microsoft",
        "email": email,
        "display_name": str(userinfo.get("displayName", "")).strip(),
        "access_token": token_payload.get("access_token", ""),
        "refresh_token": microsoft_refresh_token,
        "token_type": token_payload.get("token_type", ""),
        "scope": token_payload.get("scope", "") or " ".join(MICROSOFT_OAUTH_SCOPES),
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
    if request_contains_manual_mailbox_update(payload) and not profile_manual_mailbox_allowed(profile):
        write_monitoring_event(
            "security",
            "manual_mailbox_update_not_allowlisted",
            "warning",
            request=request,
            user_id=resolved_user_id,
            metadata={"email": profile.get("email", "")},
        )
        raise HTTPException(status_code=403, detail="Manual mailbox connection is available only for approved private clients.")
    if request_contains_manual_mailbox_update(payload):
        profile_email = str(profile.get("email", "") or "").strip().lower()
        requested_mailbox = str(payload.imap_user or profile_email).strip().lower()
        if not email_is_configured_vip_mailbox(profile_email) or requested_mailbox != configured_vip_mailbox_email():
            write_monitoring_event(
                "security",
                "manual_mailbox_update_wrong_vip_email",
                "warning",
                request=request,
                user_id=resolved_user_id,
                metadata={"email": profile_email, "requested_mailbox": requested_mailbox},
            )
            raise HTTPException(status_code=403, detail="Private mailbox connection is restricted to the approved mailbox.")
    if payload.email.strip():
        profile["email"] = payload.email.strip()
    profile["settings"] = profile_update_to_settings(payload, {**default_profile_settings(), **(profile.get("settings") or {})})
    save_profile(profile)
    return {"success": True, "profile": profile_response(profile)}


@app.post("/profile/how-to-seen")
def mark_how_to_seen(request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = mark_profile_how_to_seen(resolved_user_id)
    return {"success": True, "profile": profile_response(profile)}


@app.post("/profile/ui-hint-seen")
def mark_ui_hint_seen(request: Request, payload: UiHintSeenRequest) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    hint_map = {
        "has_seen_profile_name_prompt": "HAS_SEEN_PROFILE_NAME_PROMPT",
        "has_seen_combined_summary_email_hint": "HAS_SEEN_COMBINED_SUMMARY_EMAIL_HINT",
        "has_seen_single_summary_email_hint": "HAS_SEEN_SINGLE_SUMMARY_EMAIL_HINT",
    }
    setting_key = hint_map.get(str(payload.hint_key or "").strip())
    if not setting_key:
        raise HTTPException(status_code=400, detail="Unknown UI hint.")

    profile = load_profile_or_404(resolved_user_id)
    profile["settings"] = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    profile["settings"][setting_key] = "true"
    save_profile(profile)
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
    enforce_subscription_access(resolved_user_id, "scheduled_report")
    profile = load_profile_or_404(resolved_user_id)
    ensure_mailbox_access_ready(profile, resolved_user_id, request=request)
    settings = profile.get("settings") or {}
    normalized = normalize_schedule_payload(
        payload,
        fallback_recipient=default_report_recipient(profile, settings),
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
    enforce_subscription_access(resolved_user_id, "scheduled_report")
    profile = load_profile_or_404(resolved_user_id)
    ensure_mailbox_access_ready(profile, resolved_user_id, request=request)
    settings = profile.get("settings") or {}
    normalized = normalize_schedule_payload(
        payload,
        fallback_recipient=default_report_recipient(profile, settings),
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
    if not profile_manual_mailbox_allowed(profile):
        return {
            "connected": False,
            "status": "Not Available",
            "reason": "manual_mailbox_not_allowed",
        }

    settings = apply_provider_defaults(
        merge_stored_settings(default_profile_settings(), profile.get("settings") or {}),
        profile.get("email", ""),
    )

    def mark_mailbox_unconfirmed() -> None:
        stored_settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
        if str(stored_settings.get("MAILBOX_CONNECTION_CONFIRMED", "false")).lower() == "false":
            return
        stored_settings["MAILBOX_CONNECTION_CONFIRMED"] = "false"
        profile["settings"] = stored_settings
        save_profile(profile)

    email = str(settings.get("IMAP_USER", "")).strip()
    password = str(settings.get("IMAP_PASSWORD", "")).strip()
    server = str(settings.get("IMAP_SERVER", "")).strip()
    port = int(str(settings.get("IMAP_PORT", "993")).strip() or "993")

    if not all([email, password, server]):
        mark_mailbox_unconfirmed()
        return {
            "connected": False,
            "status": "Not Connected",
            "reason": "missing_credentials",
        }

    if not mailbox_login_succeeds(server, port, email, password):
        mark_mailbox_unconfirmed()
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


def mailbox_login_succeeds(server: str, port: int, email: str, password: str) -> bool:
    try:
        mail = imaplib.IMAP4_SSL(server, port)
        try:
            mail.login(email, password)
            mail.logout()
            return True
        except Exception:
            try:
                mail.shutdown()
            except Exception:
                pass
            return False
    except Exception:
        return False


@app.post("/mailbox/vip-password")
def save_vip_mailbox_password(
    payload: VipMailboxPasswordRequest,
    request: Request,
    user_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, user_id)
    profile = load_profile_or_404(resolved_user_id)
    email = str(profile.get("email", "") or "").strip().lower()
    google_connected = bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token"))
    microsoft_connected = bool((profile.get("microsoft_oauth") or {}).get("refresh_token") or (profile.get("microsoft_oauth") or {}).get("access_token"))

    if google_connected or microsoft_connected or not email_is_configured_vip_mailbox(email):
        write_monitoring_event(
            "security",
            "vip_mailbox_password_update_denied",
            "warning",
            request=request,
            user_id=resolved_user_id,
            metadata={"email": email},
        )
        raise HTTPException(status_code=403, detail="Private mailbox setup is available only for the approved private client.")

    mailbox_password = str(payload.mailbox_password or "")
    if not mailbox_password.strip():
        raise HTTPException(status_code=400, detail="Enter your 263 mail password or authorization code first.")

    settings = apply_vip_manual_mailbox_preconfiguration(
        merge_stored_settings(default_profile_settings(), profile.get("settings") or {}),
        email,
    )
    server = str(settings.get("IMAP_SERVER", VIP_263_IMAP_SERVER)).strip() or VIP_263_IMAP_SERVER
    port = int(str(settings.get("IMAP_PORT", VIP_263_IMAP_PORT)).strip() or VIP_263_IMAP_PORT)
    mailbox_user = str(settings.get("IMAP_USER", email)).strip() or email
    if not mailbox_login_succeeds(server, port, mailbox_user, mailbox_password):
        write_monitoring_event(
            "summarizer",
            "vip_mailbox_password_validation_failed",
            "warning",
            request=request,
            user_id=resolved_user_id,
            metadata={"email": email, "imap_server": server, "imap_port": port},
        )
        raise HTTPException(status_code=400, detail="Incorrect 263 mail password or authorization code.")

    settings["IMAP_PASSWORD"] = mailbox_password
    settings["SMTP_PASSWORD"] = mailbox_password
    settings["MAILBOX_CONNECTION_CONFIRMED"] = "true"
    profile["settings"] = settings
    save_profile(profile)
    return {"success": True, "profile": profile_response(profile)}


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

    delivery_channel = "email"

    recipient_email = str(fallback_recipient or "").strip()
    recipient_phone = ""
    if not is_valid_email(recipient_email):
        raise HTTPException(status_code=400, detail="A valid recipient_email is required for email delivery.")

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
            detail="Google sign-in is temporarily unavailable. Please contact Discere support if this keeps happening.",
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
            detail="Microsoft sign-in is temporarily unavailable. Please contact Discere support if this keeps happening.",
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
    user_id = str(profile.get("user_id", "") or "")
    refresh_token = str(google_oauth.get("refresh_token", "")).strip()
    if not refresh_token:
        write_monitoring_event("oauth", "google_missing_refresh_token", "error", user_id=user_id)
        raise reconnect_error(
            "google",
            "refresh_token",
            "Google access needs a refreshed Google sign-in for this account.",
        )

    config = get_google_oauth_config()
    try:
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
    except HTTPException as exc:
        write_monitoring_event("oauth", "google_token_refresh_failed", "error", user_id=user_id, metadata={"detail": exc.detail})
        raise
    new_access_token = str(token_payload.get("access_token", "")).strip()
    if not new_access_token:
        write_monitoring_event("oauth", "google_refresh_missing_access_token", "error", user_id=user_id)
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


def microsoft_oauth_has_scope(profile: Dict[str, Any], required_scope: str) -> bool:
    microsoft_oauth = profile.get("microsoft_oauth") or {}
    scopes = {scope.lower() for scope in parse_oauth_scope_text(microsoft_oauth.get("scope", ""))}
    required = required_scope.lower()
    required_short = required.rsplit("/", 1)[-1]
    return required in scopes or required_short in {scope.rsplit("/", 1)[-1] for scope in scopes}


def is_microsoft_reconnect_error_text(value: Any) -> bool:
    lower = str(value or "").lower()
    return (
        "microsoft mailbox access expired" in lower
        or "microsoft mailbox access needs" in lower
        or "microsoft access needs" in lower
        or "microsoft graph request failed" in lower
        or ("microsoft" in lower and "http error 401" in lower)
        or ("microsoft" in lower and "unauthorized" in lower)
        or ("microsoft" in lower and "unauthenticated" in lower)
        or ("microsoft" in lower and "invalid authentication credentials" in lower)
        or ("microsoft" in lower and "invalidauthenticationtoken" in lower)
        or ("microsoft" in lower and "insufficient permission" in lower)
        or ("microsoft" in lower and "insufficient privileges" in lower)
        or "aadsts65001" in lower
        or "consent_required" in lower
    )


def microsoft_reconnect_url(profile: Dict[str, Any], next_url: str = "/dashboard") -> str:
    email = (
        str((profile.get("microsoft_oauth") or {}).get("email", "") or "").strip()
        or str(profile.get("email", "") or "").strip()
        or str((profile.get("settings") or {}).get("IMAP_USER", "") or "").strip()
    )
    query = {
        "next": next_url or "/dashboard",
        "prompt": "consent",
        "force_reconsent": "true",
    }
    if email:
        query["login_hint"] = email
    return f"/auth/microsoft/start?{urlencode(query)}"


def refresh_microsoft_access_token(profile: Dict[str, Any]) -> str:
    microsoft_oauth = profile.get("microsoft_oauth") or {}
    user_id = str(profile.get("user_id", "") or "")
    refresh_token = str(microsoft_oauth.get("refresh_token", "")).strip()
    if not refresh_token:
        write_monitoring_event("oauth", "microsoft_missing_refresh_token", "error", user_id=user_id)
        raise reconnect_error(
            "microsoft",
            "refresh_token",
            "Microsoft access needs a refreshed Microsoft sign-in for this account.",
            microsoft_reconnect_url(profile),
        )

    config = get_microsoft_oauth_config()
    try:
        token_payload = post_form_json(
            f"https://login.microsoftonline.com/{config['tenant']}/oauth2/v2.0/token",
            {
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": " ".join(MICROSOFT_MAILBOX_TOKEN_SCOPES),
            },
            error_prefix="Microsoft token refresh failed",
        )
    except HTTPException as exc:
        write_monitoring_event("oauth", "microsoft_token_refresh_failed", "error", user_id=user_id, metadata={"detail": exc.detail})
        detail = str(exc.detail or "")
        detail_lower = detail.lower()
        if "aadsts65001" in detail_lower or "consent_required" in detail_lower or "invalid_grant" in detail_lower:
            raise reconnect_error(
                "microsoft",
                "consent_required",
                "Microsoft mailbox access needs approval. Reconnect Microsoft and approve mailbox access. If this keeps happening, the Microsoft account may need admin approval.",
                microsoft_reconnect_url(profile),
            ) from exc
        raise
    new_access_token = str(token_payload.get("access_token", "")).strip()
    if not new_access_token:
        write_monitoring_event("oauth", "microsoft_refresh_missing_access_token", "error", user_id=user_id)
        raise HTTPException(status_code=500, detail="Microsoft token refresh did not return an access token.")

    microsoft_oauth["access_token"] = new_access_token
    maybe_refresh_token = str(token_payload.get("refresh_token", "")).strip()
    if maybe_refresh_token:
        microsoft_oauth["refresh_token"] = maybe_refresh_token
    microsoft_oauth["scope"] = token_payload.get("scope") or microsoft_oauth.get("scope") or " ".join(MICROSOFT_MAILBOX_TOKEN_SCOPES)
    if not microsoft_oauth_has_scope({"microsoft_oauth": microsoft_oauth}, REQUIRED_MICROSOFT_MAIL_SCOPE):
        write_monitoring_event(
            "oauth",
            "microsoft_refresh_missing_mail_scope",
            "error",
            user_id=user_id,
            metadata={"required_scope": REQUIRED_MICROSOFT_MAIL_SCOPE},
        )
        raise reconnect_error(
            "microsoft",
            "read_mailbox",
            "Microsoft mailbox access needs approval. Reconnect Microsoft and approve mailbox access. If this keeps happening, the Microsoft account may need admin approval.",
            microsoft_reconnect_url(profile),
        )
    microsoft_oauth["updated_at"] = datetime.now().isoformat()
    profile["microsoft_oauth"] = microsoft_oauth
    save_profile(profile)
    return new_access_token


def password_mailbox_is_configured(profile: Dict[str, Any]) -> bool:
    settings = apply_provider_defaults(
        merge_stored_settings(default_profile_settings(), profile.get("settings") or {}),
        str(profile.get("email", "") or ""),
    )
    return bool(
        str(settings.get("MAILBOX_CONNECTION_CONFIRMED", "false")).strip().lower() == "true"
        and str(settings.get("IMAP_SERVER", "")).strip()
        and str(settings.get("IMAP_USER", "")).strip()
        and str(settings.get("IMAP_PASSWORD", "")).strip()
    )


def ensure_mailbox_access_ready(
    profile: Dict[str, Any],
    user_id: str,
    request: Optional[Request] = None,
    refresh_oauth: bool = False,
) -> None:
    google_oauth = profile.get("google_oauth") or {}
    microsoft_oauth = profile.get("microsoft_oauth") or {}
    google_connected = bool(google_oauth.get("refresh_token") or google_oauth.get("access_token"))
    microsoft_connected = bool(microsoft_oauth.get("refresh_token") or microsoft_oauth.get("access_token"))

    if google_connected:
        if not str(google_oauth.get("refresh_token", "")).strip():
            raise reconnect_error(
                "google",
                "refresh_token",
                "Google mailbox access needs to be refreshed for this account. Sign out and sign back in with Google to grant Gmail permissions.",
            )
        if not google_oauth_has_scope(profile, REQUIRED_GOOGLE_READ_SCOPE):
            write_monitoring_event(
                "oauth",
                "google_missing_read_scope",
                "error",
                request=request,
                user_id=user_id,
                metadata={"required_scope": REQUIRED_GOOGLE_READ_SCOPE},
            )
            raise reconnect_error(
                "google",
                "read_mailbox",
                "Google mailbox access needs to be refreshed for this account. Sign out and sign back in with Google to grant Gmail permissions.",
            )
        if refresh_oauth:
            refresh_google_access_token(profile)
        return

    if microsoft_connected:
        if not str(microsoft_oauth.get("refresh_token", "")).strip():
            raise reconnect_error(
                "microsoft",
                "refresh_token",
                "Microsoft mailbox access needs to be refreshed for this account. Reconnect Microsoft and approve mailbox permissions.",
                microsoft_reconnect_url(profile),
            )
        if not microsoft_oauth_has_scope(profile, REQUIRED_MICROSOFT_MAIL_SCOPE):
            write_monitoring_event(
                "oauth",
                "microsoft_missing_mail_scope",
                "error",
                request=request,
                user_id=user_id,
                metadata={"required_scope": REQUIRED_MICROSOFT_MAIL_SCOPE},
            )
            raise reconnect_error(
                "microsoft",
                "read_mailbox",
                "Microsoft mailbox access needs to be refreshed for this account. Reconnect Microsoft and approve mailbox permissions.",
                microsoft_reconnect_url(profile),
            )
        if refresh_oauth:
            refresh_microsoft_access_token(profile)
        return

    if not profile_manual_mailbox_allowed(profile):
        write_monitoring_event(
            "security",
            "password_mailbox_run_not_allowlisted",
            "warning",
            request=request,
            user_id=user_id,
            metadata={"email": profile.get("email", "")},
        )
        raise HTTPException(status_code=403, detail="Use Google or Microsoft sign-in to connect your mailbox.")

    if not password_mailbox_is_configured(profile):
        write_monitoring_event(
            "summarizer",
            "password_mailbox_not_connected",
            "warning",
            request=request,
            user_id=user_id,
        )
        raise HTTPException(
            status_code=400,
            detail="Mailbox connection is not ready. Contact Discere support to finish the private mailbox setup.",
        )


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
        normalized = normalize_microsoft_display_email(candidate)
        if normalized and not is_microsoft_guest_upn(normalized):
            return normalized
    return normalize_microsoft_display_email(candidates[0]) if candidates else ""


def default_profile_settings() -> Dict[str, str]:
    settings = {
        "FIRST_NAME": "",
        "LAST_NAME": "",
        "HOW_TO_SEEN": "false",
        "HAS_SEEN_PROFILE_NAME_PROMPT": "false",
        "HAS_SEEN_COMBINED_SUMMARY_EMAIL_HINT": "false",
        "HAS_SEEN_SINGLE_SUMMARY_EMAIL_HINT": "false",
        "TERMS_ACCEPTED_AT": "",
        "PRIVACY_ACCEPTED_AT": "",
        "TERMS_VERSION_ACCEPTED": "",
        "PRIVACY_VERSION_ACCEPTED": "",
        "EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM": "false",
        "REPORT_EMAIL_MODE": REPORT_EMAIL_MODE_FULL,
        "BACKGROUND_THEME": DEFAULT_BACKGROUND_THEME,
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "OPENAI_MODEL": "gpt-5.1",
        "WHITELIST_SENDERS": "",
        "CONTACT_PROFILES": "{}",
        "MAILBOX_CONNECTION_CONFIRMED": "false",
        "SUMMARY_STYLE_PREFERENCES": "[]",
        "SUBSCRIPTION_STATUS": "",
        "SUBSCRIPTION_TRIAL_STARTED_AT": "",
        "SUBSCRIPTION_TRIAL_ENDS_AT": "",
        "SUBSCRIPTION_ACTIVATED_AT": "",
        "STRIPE_CUSTOMER_ID": "",
        "STRIPE_SUBSCRIPTION_ID": "",
        "IMAP_SERVER": "",
        "IMAP_PORT": "993",
        "IMAP_USER": "",
        "IMAP_PASSWORD": "",
        "IMAP_FOLDER": "INBOX",
        "SMTP_HOST": "",
        "SMTP_PORT": "465",
        "SMTP_USER": "",
        "SMTP_PASSWORD": "",
        "SUMMARY_RECIPIENT": "",
    }
    base_env = BASE_DIR / ".env"
    if base_env.exists():
        env_values = read_env_key_values(base_env)
        for key, value in env_values.items():
            if key in ACCOUNT_SCOPED_SETTING_KEYS:
                continue
            if not settings.get(key):
                settings[key] = value
    return settings


def billing_exempt_emails() -> set[str]:
    configured = {
        item.strip().lower()
        for item in os.getenv("EMAIL_SUMMARIZER_BILLING_EXEMPT_EMAILS", "").split(",")
        if item.strip()
    }
    return DEFAULT_BILLING_EXEMPT_EMAILS | configured


def _parse_subscription_datetime(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    return parsed


def _profile_billing_emails(profile: Dict[str, Any]) -> set[str]:
    candidates = {
        str(profile.get("email", "") or "").strip().lower(),
        str((profile.get("google_oauth") or {}).get("email", "") or "").strip().lower(),
        str((profile.get("microsoft_oauth") or {}).get("email", "") or "").strip().lower(),
    }
    normalized_microsoft = normalize_microsoft_display_email(str((profile.get("microsoft_oauth") or {}).get("email", "") or ""))
    if normalized_microsoft:
        candidates.add(normalized_microsoft.strip().lower())
    return {email for email in candidates if email}


def is_billing_exempt_profile(profile: Dict[str, Any]) -> bool:
    return bool(_profile_billing_emails(profile) & billing_exempt_emails())


def ensure_subscription_settings(profile: Dict[str, Any]) -> bool:
    settings = merge_stored_settings(default_profile_settings(), profile.get("settings") or {})
    now = datetime.now(ZoneInfo("UTC")).replace(tzinfo=None)
    changed = settings != (profile.get("settings") or {})

    if not str(settings.get("SUBSCRIPTION_TRIAL_STARTED_AT", "") or "").strip():
        settings["SUBSCRIPTION_TRIAL_STARTED_AT"] = now.isoformat()
        changed = True
    if not str(settings.get("SUBSCRIPTION_TRIAL_ENDS_AT", "") or "").strip():
        trial_start = _parse_subscription_datetime(settings.get("SUBSCRIPTION_TRIAL_STARTED_AT")) or now
        settings["SUBSCRIPTION_TRIAL_ENDS_AT"] = (trial_start + timedelta(days=SUBSCRIPTION_TRIAL_DAYS)).isoformat()
        changed = True
    if not str(settings.get("SUBSCRIPTION_STATUS", "") or "").strip():
        settings["SUBSCRIPTION_STATUS"] = "trialing"
        changed = True

    profile["settings"] = settings
    return changed


def subscription_status_for_profile(profile: Dict[str, Any], *, persist: bool = False) -> Dict[str, Any]:
    changed = ensure_subscription_settings(profile)
    settings = profile.get("settings") or {}
    now = datetime.now(ZoneInfo("UTC")).replace(tzinfo=None)
    raw_status = str(settings.get("SUBSCRIPTION_STATUS", "") or "trialing").strip().lower()
    trial_started_at = _parse_subscription_datetime(settings.get("SUBSCRIPTION_TRIAL_STARTED_AT"))
    trial_ends_at = _parse_subscription_datetime(settings.get("SUBSCRIPTION_TRIAL_ENDS_AT"))
    exempt = is_billing_exempt_profile(profile)

    active_statuses = {"active", "member", "paid", "trial_exempt"}
    if exempt:
        normalized_status = "member"
        label = "Member"
        requires_subscription = False
        days_remaining = None
        message = "You have full access to Discere for testing."
    elif raw_status in active_statuses:
        normalized_status = "member"
        label = "Member"
        requires_subscription = False
        days_remaining = None
        message = "Your Discere subscription is active."
    elif trial_ends_at and trial_ends_at > now:
        normalized_status = "trialing"
        label = "Free Trial"
        requires_subscription = False
        remaining_seconds = max(0, int((trial_ends_at - now).total_seconds()))
        days_remaining = max(1, (remaining_seconds + 86399) // 86400)
        message = f"Your free trial has {days_remaining} day{'s' if days_remaining != 1 else ''} remaining."
    else:
        normalized_status = "expired"
        label = "Trial Ended"
        requires_subscription = True
        days_remaining = 0
        message = "Your free trial has ended. Subscribe to continue using Discere."

    if raw_status != normalized_status and normalized_status in {"expired", "member"}:
        settings["SUBSCRIPTION_STATUS"] = normalized_status
        changed = True

    if persist and changed:
        save_profile(profile)

    return {
        "status": normalized_status,
        "label": label,
        "is_exempt": exempt,
        "requires_subscription": requires_subscription,
        "trial_started_at": trial_started_at.isoformat() if trial_started_at else "",
        "trial_ends_at": trial_ends_at.isoformat() if trial_ends_at else "",
        "trial_days": SUBSCRIPTION_TRIAL_DAYS,
        "days_remaining": days_remaining,
        "plan_name": SUBSCRIPTION_PLAN_NAME,
        "price_cents": SUBSCRIPTION_PRICE_CENTS,
        "price_label": SUBSCRIPTION_PRICE_LABEL,
        "billing_interval": "month",
        "checkout_configured": bool(os.getenv("EMAIL_SUMMARIZER_STRIPE_CHECKOUT_URL", "").strip()),
        "portal_configured": bool(os.getenv("EMAIL_SUMMARIZER_STRIPE_CUSTOMER_PORTAL_URL", "").strip()),
        "message": message,
    }


def enforce_subscription_access(user_id: str, feature: str = "feature") -> Dict[str, Any]:
    profile = load_profile_or_404(user_id)
    subscription = subscription_status_for_profile(profile, persist=True)
    if subscription.get("requires_subscription"):
        write_monitoring_event(
            "abuse",
            "subscription_required",
            "warning",
            user_id=user_id,
            metadata={"feature": feature, "status": subscription.get("status")},
        )
        raise HTTPException(
            status_code=402,
            detail={
                "code": "subscription_required",
                "message": "Your free trial has ended. Subscribe to continue using Discere.",
                "subscription": subscription,
            },
        )
    return subscription


def normalize_openai_model(value: Any) -> str:
    model = str(value or "").strip()
    # Legacy deployments defaulted to gpt-4o. Normalize those defaults to gpt-5.1.
    if not model or model == "gpt-4o":
        return "gpt-5.1"
    return model


def normalize_report_email_mode(value: Any) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in REPORT_EMAIL_MODES else REPORT_EMAIL_MODE_FULL


def normalize_background_theme(value: Any) -> str:
    theme = str(value or "").strip().lower()
    return theme if theme in BACKGROUND_THEMES else DEFAULT_BACKGROUND_THEME


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
        "how_to_seen": str(settings.get("HOW_TO_SEEN", "false")).lower() == "true",
        "has_seen_profile_name_prompt": str(settings.get("HAS_SEEN_PROFILE_NAME_PROMPT", "false")).lower() == "true",
        "has_seen_combined_summary_email_hint": str(settings.get("HAS_SEEN_COMBINED_SUMMARY_EMAIL_HINT", "false")).lower() == "true",
        "has_seen_single_summary_email_hint": str(settings.get("HAS_SEEN_SINGLE_SUMMARY_EMAIL_HINT", "false")).lower() == "true",
        "terms_accepted": bool(str(settings.get("TERMS_ACCEPTED_AT", "")).strip()),
        "privacy_accepted": bool(str(settings.get("PRIVACY_ACCEPTED_AT", "")).strip()),
        "terms_accepted_at": settings.get("TERMS_ACCEPTED_AT", ""),
        "privacy_accepted_at": settings.get("PRIVACY_ACCEPTED_AT", ""),
        "terms_version": settings.get("TERMS_VERSION_ACCEPTED", "") or TERMS_VERSION,
        "privacy_version": settings.get("PRIVACY_VERSION_ACCEPTED", "") or PRIVACY_VERSION,
        "attachment_ai_enabled": str(settings.get("EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM", "false")).lower() == "true",
        "report_email_mode": normalize_report_email_mode(settings.get("REPORT_EMAIL_MODE", REPORT_EMAIL_MODE_FULL)),
        "background_theme": normalize_background_theme(settings.get("BACKGROUND_THEME", DEFAULT_BACKGROUND_THEME)),
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
    if update.first_name.strip() or update.last_name.strip():
        settings["HAS_SEEN_PROFILE_NAME_PROMPT"] = "true"
    if update.attachment_ai_enabled is not None:
        settings["EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM"] = "true" if update.attachment_ai_enabled else "false"
    if update.report_email_mode.strip():
        settings["REPORT_EMAIL_MODE"] = normalize_report_email_mode(update.report_email_mode)
    if update.background_theme.strip():
        settings["BACKGROUND_THEME"] = normalize_background_theme(update.background_theme)
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


def apply_vip_manual_mailbox_preconfiguration(settings: Dict[str, str], email: str) -> Dict[str, str]:
    merged = dict(settings)
    if not email_is_configured_vip_mailbox(email):
        return merged

    vip_email = configured_vip_mailbox_email()
    merged.update(
        {
            "IMAP_SERVER": VIP_263_IMAP_SERVER,
            "IMAP_PORT": VIP_263_IMAP_PORT,
            "SMTP_HOST": VIP_263_SMTP_HOST,
            "SMTP_PORT": VIP_263_SMTP_PORT,
            "IMAP_FOLDER": VIP_263_IMAP_FOLDER,
            "IMAP_USER": vip_email,
            "SMTP_USER": vip_email,
            "SUMMARY_RECIPIENT": str(email or "").strip().lower(),
            "MAILBOX_CONNECTION_CONFIRMED": "false",
            "IMAP_PASSWORD": "",
            "SMTP_PASSWORD": "",
        }
    )
    return merged


def apply_provider_defaults(settings: Dict[str, str], email: str, force_outlook: bool = False) -> Dict[str, str]:
    normalized = (email or "").strip().lower()
    merged = dict(settings)
    provider_defaults = {}

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
        raise HTTPException(status_code=404, detail="Profile not found.")
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
    subscription = subscription_status_for_profile(profile, persist=True)
    settings = profile.get("settings") or settings
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
        "manual_mailbox_allowed": profile_manual_mailbox_allowed(profile),
        "auth_provider": auth_provider,
        "subscription": subscription,
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
        write_monitoring_event(
            "security",
            "unauthenticated_user_id_override",
            "warning",
            request=request,
            user_id=explicit,
        )
        raise HTTPException(status_code=401, detail="Please log in first.")
    if explicit and session_user_id and explicit != session_user_id:
        write_monitoring_event(
            "data_isolation",
            "cross_account_user_id_override",
            "critical",
            request=request,
            user_id=session_user_id,
            metadata={"requested_user_id": explicit},
        )
        raise HTTPException(status_code=403, detail="You do not have access to that user.")
    if explicit:
        return explicit
    if session_user_id:
        return session_user_id

    raise HTTPException(status_code=401, detail="Please log in first.")


def require_admin(request: Request) -> None:
    configured_key = os.getenv("EMAIL_SUMMARIZER_ADMIN_KEY", "").strip()
    provided_key = request.headers.get("x-discere-admin-key", "").strip()
    if configured_key and hmac.compare_digest(configured_key, provided_key):
        return

    raise HTTPException(status_code=403, detail="Admin access requires the internal admin key.")


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


def get_user_metadata_path(user_id: str) -> Path:
    return DATA_DIR / user_id / "metadata.json"


def get_user_processed_state_path(user_id: str) -> Path:
    return OUTPUT_ROOT_DIR / user_id / "processed_state.json"


def safe_user_file_path(base_dir: Path, file_stem: str, suffix: str, label: str) -> Path:
    clean_stem = str(file_stem or "").strip()
    if not clean_stem or "/" in clean_stem or "\\" in clean_stem or clean_stem in {".", ".."} or ".." in Path(clean_stem).parts:
        raise HTTPException(status_code=400, detail=f"Invalid {label}.")
    base_resolved = base_dir.resolve()
    candidate = (base_dir / f"{clean_stem}{suffix}").resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        raise HTTPException(status_code=403, detail=f"Invalid {label} path.")
    return candidate


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


def build_markdown_from_summary_payload(summary: Dict[str, Any]) -> str:
    existing_markdown = str(summary.get("summary_markdown") or summary.get("content_markdown") or "").strip()
    if existing_markdown:
        return existing_markdown

    sections: List[str] = []
    title = str(summary.get("title") or summary.get("summary_id") or "Summary").strip()
    if title:
        sections.append(f"# {title}")
    for section_title, key in [
        ("Executive Summary", "executive_summary"),
        ("Main Topics", "main_topics"),
        ("New Developments", "new_developments"),
        ("Action Items / Asks", "action_items"),
        ("Deadlines / Dates / Meetings", "deadlines"),
        ("Attachment Summary", "attachment_summary"),
        ("Bottom Line", "bottom_line"),
    ]:
        content = str(summary.get(key) or "").strip()
        if not content:
            continue
        sections.append(f"## {section_title}")
        sections.append(content)
    return "\n\n".join(sections).strip()


def apply_refined_markdown_to_summary(summary: Dict[str, Any], refined_markdown: str) -> Dict[str, Any]:
    refined = str(refined_markdown or "").strip()
    updated = dict(summary)
    updated["summary_markdown"] = refined
    updated["content_markdown"] = refined
    updated["executive_summary"] = extract_markdown_section(refined, "Executive Summary")
    updated["main_topics"] = extract_markdown_section(refined, "Main Topics")
    updated["new_developments"] = extract_markdown_section(refined, "New Developments")
    updated["action_items"] = extract_markdown_section(refined, "Action Items / Asks")
    updated["deadlines"] = extract_markdown_section(refined, "Deadlines / Dates / Meetings")
    updated["attachment_summary"] = extract_markdown_section(refined, "Attachment Summary")
    updated["bottom_line"] = extract_markdown_section(refined, "Bottom Line")
    updated["preview"] = summarize_preview(refined) or updated.get("preview", "")
    updated["updated_at"] = datetime.now().isoformat()
    updated["refined_at"] = updated["updated_at"]
    return updated


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


def load_last_run_summary_ids_for_user(user_id: str) -> List[str]:
    metadata_path = get_user_metadata_path(user_id)
    if not metadata_path.exists():
        return []
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        str(summary_id).strip()
        for summary_id in payload.get("last_summary_ids", [])
        if str(summary_id).strip() and not str(summary_id).strip().startswith("overall_master_")
    ]


def load_summaries_by_ids_for_user(user_id: str, summary_ids: List[str]) -> List[Dict[str, Any]]:
    tracked_contacts = {contact.strip().lower() for contact in get_contacts_for_user(user_id) if contact.strip()}
    summaries: List[Dict[str, Any]] = []
    json_summaries_dir = get_user_json_summaries_dir(user_id)
    for summary_id in summary_ids:
        clean_id = str(summary_id or "").strip()
        if not clean_id or clean_id.startswith("overall_master_"):
            continue
        summary_path = safe_user_file_path(json_summaries_dir, clean_id, ".json", "summary")
        if not summary_path.exists():
            continue
        summary = load_summary_json(summary_path)
        sender = str(summary.get("sender", "") or "").strip().lower()
        if tracked_contacts and sender not in tracked_contacts:
            continue
        summaries.append(summary)
    return summaries


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
    path.parent.mkdir(parents=True, exist_ok=True)
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


DISCERE_PRODUCT_KNOWLEDGE = """
DISCERE PRODUCT KNOWLEDGE

Purpose and core workflow:
- Discere summarizes emails from important contacts selected by the user.
- Users add tracked contacts, run the summarizer for a chosen days-back window, review generated summaries, ask AI Assistant questions, combine selected summaries, and optionally schedule recurring email summary reports.
- If the user runs the summarizer with no tracked contacts, Discere should tell them to add contacts first.
- The checkbox/select controls are for actions such as combining summaries, emailing reports, deleting summaries, or marking summaries done. A summary becomes read when the user opens/clicks it.

Contacts and summarization behavior:
- Discere is designed to process trigger emails only when the actual parsed From email matches a tracked contact.
- Gmail OAuth uses Gmail API read-only access to find and read relevant Gmail messages. Gmail OAuth does not use IMAP.
- Microsoft OAuth uses Microsoft Graph mailbox access plus refresh/offline access for scheduled runs.
- The public product supports Gmail and Microsoft/Outlook only.
- Approved private clients may have a separate manual mailbox setup, but normal public users do not see or use Mailbox Connection.
- The summarizer reconstructs thread context so a summary can include relevant messages and attachments in the thread, not only the single trigger email.

Read, done, delete, and re-summarization:
- New/unread summaries become read when the user opens and reviews them.
- Marking a summary as done keeps the summarized email IDs so Discere avoids accidentally summarizing the same email again.
- Read or done summaries have source email bodies and saved attachments purged after 20 days, while summarized email IDs remain to prevent accidental duplicate summaries.
- Deleting an individual summary removes the saved summary and related processed identifiers for emails only tied to that summary. That means the email can be rediscovered and summarized again if it still matches the user's contacts and search window.
- If a user says deleted emails keep coming back, explain that deletion is intentionally rediscovery-friendly. They should mark summaries as done instead of deleting them when they want Discere to remember that the email was already handled.
- A new email in the same thread has a new message ID and can create a fresh summary if it matches a tracked contact and the scan window.

Reports and scheduled reports:
- Manual and scheduled email reports are sent from Discere's configured report sender address, not from the user's connected Gmail, Microsoft, or mailbox account.
- Users can choose Full Report, which includes summary content in report emails, or Email Notification, which sends a generic "ready" email that links back to the dashboard without including summary content.
- Scheduled reports always create a fresh summarizer run first, then email the chosen report format to the user's connected account email.
- Saved schedules can be viewed, edited, deleted, and toggled on/off.
- Phone/SMS report delivery is not part of the current launch flow unless explicitly re-enabled later.

Subscription and billing:
- New accounts receive a 7-day free trial without entering payment information.
- After the free trial ends, summarization, AI Assistant, report delivery, and scheduled report features require a paid subscription.
- The current introductory plan is $4.99 per month.
- Some invited early users may receive free access or extended trials at Discere's discretion.
- Users can see trial or member status in Settings under Subscription.
- Testing accounts configured by Discere can be exempt from subscription enforcement.

Privacy and AI processing:
- Discere reads mailbox data needed to find emails from tracked contacts and generate summaries.
- Discere stores account settings, contacts, schedules, summaries, summarized email IDs, and limited source email data needed to operate Discere.
- Relevant email text and thread context are sent to OpenAI through the OpenAI API to generate summaries and AI answers. Attachment contents are sent to OpenAI only if AI attachment access is enabled; otherwise Discere limits attachment use to metadata such as filenames.
- OpenAI states that API inputs and outputs are not used to train or improve OpenAI models by default unless the API organization explicitly opts in. Discere has not opted in to share API inputs or outputs for OpenAI model training or improvement, so Discere's OpenAI API inputs and outputs are not used to train or improve OpenAI models. OpenAI may still retain limited API data, which can include prompts and responses, for abuse monitoring, safety, legal compliance, and API operation under its published API data controls.
- OpenAI's published API data controls say abuse-monitoring logs may include customer content such as prompts and responses and are retained for up to 30 days by default, unless longer retention is required by law or needed to protect OpenAI's services or others from harm.
- Discere does not sell Google or Microsoft user data and does not use mailbox data for advertising.

Security and account controls:
- OAuth tokens and mailbox credentials are encrypted and stored where needed.
- Discere uses account isolation so users should only access their own summaries, contacts, settings, attachments, schedules, and related account data.
- Users can delete individual summaries from the dashboard.
- Users can delete their account from Settings. Account deletion removes account data, contacts, schedules, summaries, source email data, attachments, and related user records, except limited records retained where reasonably necessary for security, legal compliance, dispute resolution, fraud prevention, or backup integrity.
- Users can revoke Google or Microsoft OAuth access from their provider account settings.
- No internet service is risk-free. Sensitive legal, medical, financial, government, board-level, regulated, or highly confidential inboxes should be reviewed carefully before connecting.

Limits and errors:
- Usage limits exist to prevent runaway AI/API cost, but normal users should only see limit messaging after a limit is hit.
- If OAuth scope errors occur, users may need to log out and log back in with Google or Microsoft and approve the requested permissions.
- If report email sending is not working, users should contact Discere support.

Terms-style plain English:
- Users must have the legal right to connect each mailbox and process the emails/attachments made available through that connection.
- AI outputs can be incomplete or inaccurate and should be reviewed before relying on them for legal, financial, operational, or sensitive decisions.
- Discere is a summarization and reporting service, not legal, financial, medical, tax, security, employment, or compliance advice.
""".strip()


def is_discere_product_question(question: str) -> bool:
    text = str(question or "").lower()
    product_terms = [
        "discere",
        "privacy",
        "security",
        "terms",
        "policy",
        "oauth",
        "gmail",
        "microsoft",
        "outlook",
        "imap",
        "openai",
        "ai provider",
        "train",
        "data",
        "delete",
        "deleted",
        "again",
        "resummar",
        "re-summar",
        "rediscover",
        "done",
        "read",
        "schedule",
        "scheduled",
        "report",
        "sender",
        "subscription",
        "trial",
        "billing",
        "payment",
        "price",
        "pricing",
        "mailbox connection",
        "attachment",
        "account",
        "contact",
        "contacts",
        "summarizer",
        "how does",
        "how do i",
        "why",
    ]
    return any(term in text for term in product_terms)


PUBLIC_DISCERE_CHAT_KNOWLEDGE = """
PUBLIC DISCERE KNOWLEDGE

What Discere does:
- Discere helps busy people keep up with important email conversations.
- Users choose important senders/contacts. Discere checks emails from those people and turns the useful parts into organized summaries.
- Discere is not meant to summarize the whole inbox by default.
- If there are no tracked contacts, users should add contacts before running the summarizer.
- Tracked contacts are not notified when they are added or summarized.

Who it is for:
- Discere is designed for people who get too many important emails and want the main point, actions, deadlines, and updates quickly.
- Explain things simply for adults who may not follow every new AI tool but can benefit from easier email review.

How to start:
- Click Log In.
- Sign in with Gmail or Microsoft/Outlook.
- Add important contacts.
- Run the summarizer with the play button.
- Open summaries, mark handled emails as done, and use scheduled summaries if the user wants routine email reports.

Main features:
- Contacts: the people whose emails Discere should watch.
- Summarizer: checks recent emails from tracked contacts and creates summaries.
- AI Assistant: inside the dashboard, users can ask questions about their saved summaries and emails.
- Scheduled summaries: users can receive routine Discere report emails.
- Reports: sent from Discere to the user's connected account email, not from the user's personal mailbox.
- Full Report includes summary content in the email. Email Notification sends a simple ready message without summary content.

Privacy and data:
- Gmail uses Gmail API read-only access.
- Microsoft/Outlook uses Microsoft OAuth and Microsoft Graph mailbox read access.
- Discere reads mailbox data needed to find and summarize emails from tracked contacts.
- Relevant email text is sent to OpenAI through the OpenAI API to generate summaries and AI answers.
- Discere has not opted in to share API inputs or outputs for OpenAI model training or improvement, so Discere's OpenAI API inputs and outputs are not used to train or improve OpenAI models.
- Attachment contents are sent to AI only if AI Attachment Access is turned on. If it is off, Discere only uses basic attachment references such as filenames.
- Discere stores account settings, contacts, schedules, summaries, summarized email IDs, and limited source email data needed to operate the service.
- Read or done summaries have source email bodies and saved attachments purged after 20 days, while summarized email IDs can remain to avoid duplicate summaries.
- Discere does not sell Google or Microsoft user data and does not use mailbox data for advertising.
- Users can delete individual summaries or delete their account in Settings. Limited records may remain where reasonably necessary for security, legal compliance, dispute resolution, fraud prevention, or backup integrity.

Billing:
- New accounts receive a 7-day free trial without entering payment information.
- After the trial, continued access to summarization, AI Assistant, report delivery, and scheduled reports requires a paid subscription.
- The introductory plan is $4.99 per month unless checkout shows a different price.
- Some invited early users may receive free access or extended trials at Discere's discretion.

Public chat limits:
- This public website chat can explain Discere, but it cannot see a visitor's inbox, account, summaries, contacts, schedules, or billing status.
- For account-specific help, tell users to log in and use the dashboard or contact support@discere-ai.com.
""".strip()


def build_public_chat_history(conversation: List[Dict[str, str]], max_chars: int = 2500) -> str:
    return build_recent_chat_history(conversation, max_chars=max_chars)


def clean_chat_answer_text(text: str) -> str:
    cleaned = str(text or "")
    cleaned = re.sub(r"(?m)^\s*#{1,6}\s*", "", cleaned)
    cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)
    cleaned = re.sub(r"(?<!\w)\*(.*?)\*(?!\w)", r"\1", cleaned)
    cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
    cleaned = re.sub(r"(?m)^\s*[-*]\s+", "• ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def build_recent_chat_history(conversation: List[Dict[str, str]], max_chars: int = 6000) -> str:
    blocks: List[str] = []
    total = 0
    for entry in list(conversation or [])[-12:]:
        role = str(entry.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        text = _compact_for_chat(str(entry.get("text") or ""), 1000)
        if not text:
            continue
        block = f"{role.upper()}: {_to_ascii_safe(text)}"
        if total + len(block) > max_chars and blocks:
            break
        blocks.append(block)
        total += len(block) + 2
    return "\n\n".join(blocks)


def render_inline_markdown_html(text: str) -> str:
    escaped = escape(str(text or ""))
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


REPORT_SECTION_LABELS = {
    "executive summary": "Executive Summary",
    "main topics": "Key Points",
    "main themes": "Key Points",
    "new developments": "Updates",
    "action items / asks": "Action Items",
    "key action items": "Action Items",
    "deadlines / dates / meetings": "Dates & Deadlines",
    "deadlines / dates": "Dates & Deadlines",
    "notable attachments": "Attachments",
    "attachment summary": "Attachments",
    "attachments": "Attachments",
    "bottom line": "Bottom Line",
}

REPORT_SECTION_ORDER = [
    "Executive Summary",
    "Key Points",
    "Updates",
    "Action Items",
    "Dates & Deadlines",
    "Attachments",
    "Bottom Line",
]


def clean_markdown_heading_text(text: str) -> str:
    return re.sub(r"^\s*#{1,6}\s*", "", str(text or "").strip()).strip()


def normalize_report_section_label(title: str) -> str:
    cleaned = clean_markdown_heading_text(title)
    return REPORT_SECTION_LABELS.get(cleaned.lower(), cleaned)


def split_contact_title(title: str) -> tuple[str, str]:
    cleaned = clean_markdown_heading_text(title) or "Summary"
    match = re.match(r"^(?P<name>.+?)\s*\((?P<email>[^()\s]+@[^()\s]+)\)\s*$", cleaned)
    if match:
        return match.group("name").strip(), match.group("email").strip()
    if is_valid_email(cleaned):
        return cleaned, cleaned
    return cleaned, ""


def append_report_section(sections: Dict[str, str], title: str, lines: List[str]) -> None:
    label = normalize_report_section_label(title)
    content = "\n".join(line for line in lines).strip()
    if not label or not content:
        return
    if label in sections and sections[label].strip():
        sections[label] = f"{sections[label].strip()}\n{content}"
    else:
        sections[label] = content


def parse_report_markdown_cards(markdown: str) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    current_section = "Executive Summary"
    current_lines: List[str] = []

    def flush_section() -> None:
        nonlocal current_lines
        if current is not None:
            append_report_section(current["sections"], current_section, current_lines)
        current_lines = []

    def flush_card() -> None:
        nonlocal current
        flush_section()
        if current is None:
            return
        if any(str(value).strip() for value in current["sections"].values()):
            cards.append(current)
        current = None

    for raw_line in str(markdown or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("## "):
            flush_card()
            name, email = split_contact_title(stripped[3:])
            current = {
                "title": name,
                "email": email,
                "updated_at": "",
                "sections": {},
            }
            current_section = "Executive Summary"
            current_lines = []
            continue
        if stripped.startswith("# "):
            continue
        if current is None:
            if not stripped:
                continue
            current = {"title": "Summary", "email": "", "updated_at": "", "sections": {}}
        if stripped.startswith("### "):
            flush_section()
            current_section = normalize_report_section_label(stripped[4:])
            current_lines = []
            continue
        updated_match = re.match(r"^Updated:\s*(.+)$", stripped, flags=re.IGNORECASE)
        if updated_match and not current.get("updated_at"):
            current["updated_at"] = updated_match.group(1).strip()
            continue
        current_lines.append(clean_markdown_heading_text(line) if stripped.startswith("#") else line)

    flush_card()
    return cards


def summary_to_report_card(summary: Dict[str, Any], *, executive_only: bool = False) -> Dict[str, Any]:
    title = clean_summary_title(summary.get("title", ""), summary.get("summary_id", "Summary"))
    name, email = split_contact_title(title)
    sections: Dict[str, str] = {}
    section_map = [("Executive Summary", "executive_summary")]
    if not executive_only:
        section_map.extend(
            [
                ("Key Points", "main_topics"),
                ("Updates", "new_developments"),
                ("Action Items", "action_items"),
                ("Dates & Deadlines", "deadlines"),
                ("Attachments", "attachment_summary"),
                ("Bottom Line", "bottom_line"),
            ]
        )
    for label, key in section_map:
        content = str(summary.get(key, "") or "").strip()
        if content:
            sections[label] = content
    if executive_only and not sections:
        sections["Executive Summary"] = "No executive summary is available for this summary."
    return {
        "title": name,
        "email": email or str(summary.get("sender") or "").strip(),
        "updated_at": str(summary.get("updated_at") or "").strip(),
        "sections": sections,
    }


def render_report_text_block(text: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    blocks: List[str] = []
    bullet_items: List[str] = []

    def flush_bullets() -> None:
        nonlocal bullet_items
        if not bullet_items:
            return
        blocks.append(
            "<ul style='margin:0 0 12px 0; padding-left:22px;'>"
            + "".join(
                f"<li style='margin:0 0 7px 0; line-height:1.55; color:#191917; font-size:15px;'>{render_inline_markdown_html(item)}</li>"
                for item in bullet_items
            )
            + "</ul>"
        )
        bullet_items = []

    for line in lines:
        cleaned = clean_markdown_heading_text(line)
        bullet_match = re.match(r"^(?:[-*•]\s+)(.+)$", cleaned)
        if bullet_match:
            bullet_items.append(bullet_match.group(1).strip())
            continue
        flush_bullets()
        blocks.append(
            f"<p style='margin:0 0 12px 0; line-height:1.65; color:#191917; font-size:15px;'>{render_inline_markdown_html(cleaned)}</p>"
        )
    flush_bullets()
    return "".join(blocks)


def render_report_email_html(title: str, cards: List[Dict[str, Any]], intro: str = "Here are your latest summaries.") -> str:
    card_html: List[str] = []
    for card in cards:
        sections = card.get("sections") or {}
        section_html: List[str] = []
        ordered_labels = [label for label in REPORT_SECTION_ORDER if str(sections.get(label, "")).strip()]
        ordered_labels.extend(label for label in sections if label not in ordered_labels and str(sections.get(label, "")).strip())
        for label in ordered_labels:
            block = render_report_text_block(str(sections.get(label, "") or ""))
            if not block:
                continue
            section_html.append(
                "<section style='margin:18px 0 0 0;'>"
                f"<h3 style='margin:0 0 8px 0; color:#111; font-size:14px; letter-spacing:0.08em; text-transform:uppercase;'>{escape(label)}</h3>"
                f"<div>{block}</div>"
                "</section>"
            )
        if not section_html:
            continue
        display_title = str(card.get("title") or "Summary").strip()
        email = str(card.get("email") or "").strip()
        updated = str(card.get("updated_at") or "").strip()
        meta_parts = []
        if email and email != display_title:
            meta_parts.append(escape(email))
        if updated:
            meta_parts.append(f"Updated: {escape(updated)}")
        meta_html = (
            f"<p style='margin:6px 0 0 0; color:#6f6d66; font-size:13px; line-height:1.5;'>{' · '.join(meta_parts)}</p>"
            if meta_parts
            else ""
        )
        card_html.append(
            "<article style='background:#ffffff; border:1px solid #deded8; border-radius:18px; padding:22px 24px; margin:0 0 18px 0;'>"
            f"<h2 style='margin:0; color:#111; font-size:22px; line-height:1.2; letter-spacing:-0.03em;'>{escape(display_title)}</h2>"
            f"{meta_html}"
            + "".join(section_html)
            + "</article>"
        )

    if not card_html:
        card_html.append(
            "<article style='background:#ffffff; border:1px solid #deded8; border-radius:18px; padding:22px 24px;'>"
            "<p style='margin:0; color:#555; line-height:1.6;'>No summary content was available for this report.</p>"
            "</article>"
        )

    return (
        "<html><body style='margin:0; padding:0; background:#ffffff;'>"
        "<div style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; color:#111; "
        "max-width:760px; margin:0 auto; padding:28px 22px; background:#ffffff;'>"
        + render_email_brand_header(title or "Discere Email Summary", intro)
        + "".join(card_html)
        + "</div></body></html>"
    )


def render_report_email_text(title: str, cards: List[Dict[str, Any]], max_chars: int = 1400) -> str:
    blocks: List[str] = [str(title or "Discere Email Summary").strip(), "Here are your latest summaries.", ""]
    for card in cards:
        card_title = str(card.get("title") or "Summary").strip()
        email = str(card.get("email") or "").strip()
        updated = str(card.get("updated_at") or "").strip()
        blocks.append(card_title)
        if email and email != card_title:
            blocks.append(email)
        if updated:
            blocks.append(f"Updated: {updated}")
        sections = card.get("sections") or {}
        ordered_labels = [label for label in REPORT_SECTION_ORDER if str(sections.get(label, "")).strip()]
        ordered_labels.extend(label for label in sections if label not in ordered_labels and str(sections.get(label, "")).strip())
        for label in ordered_labels:
            lines = [clean_markdown_heading_text(line) for line in str(sections.get(label, "") or "").splitlines()]
            lines = [line for line in lines if line.strip()]
            if not lines:
                continue
            blocks.append("")
            blocks.append(label)
            for line in lines:
                cleaned = re.sub(r"\*\*(.+?)\*\*", r"\1", line).strip()
                bullet_match = re.match(r"^(?:[-*•]\s+)(.+)$", cleaned)
                blocks.append(f"- {bullet_match.group(1).strip()}" if bullet_match else cleaned)
        blocks.append("")
    text = _to_ascii_safe("\n".join(blocks).strip())
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "\n... [continued in email/app]"
    return text


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
        write_monitoring_event(
            "data_isolation",
            "attachment_access_denied",
            "critical",
            request=request,
            user_id=resolved_user_id,
            metadata={"requested_path": str(requested_path)},
        )
        raise HTTPException(status_code=403, detail="You do not have access to that attachment.")

    if not requested_path.exists() or not requested_path.is_file():
        raise HTTPException(status_code=404, detail="Attachment not found.")

    return FileResponse(requested_path, filename=requested_path.name)


@app.api_route("/public-report", methods=["GET", "HEAD"])
def get_public_report(
    user_id: str = Query(...),
    path: str = Query(...),
    expires: int = Query(...),
    sig: str = Query(...),
) -> FileResponse:
    if not public_reports_enabled():
        raise HTTPException(status_code=404, detail="Public report links are not available.")
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
    summary_path = safe_user_file_path(get_user_json_summaries_dir(user_id), summary_id, ".json", "summary id")
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Summary not found.")

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

        email_path = safe_user_file_path(get_user_json_emails_dir(user_id), email_id, ".json", "email id")
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

    if not blocks:
        return ""

    header = (
        f"TOTAL SUMMARIES INCLUDED: {len(summaries)}\n"
        f"TOTAL EMAIL RECORDS INCLUDED: {len(emails)}\n"
        "These are saved historical summaries and linked source emails for this account. "
        "Answer only from this context.\n"
    )
    return _to_ascii_safe(header + "\n\n".join(blocks))


def render_summary_email_html(summary: Dict[str, Any]) -> str:
    return render_report_email_html(
        "Discere Email Summary",
        [summary_to_report_card(summary)],
        intro="Here is the full summary you requested.",
    )


def default_report_recipient(profile: Dict[str, Any], settings: Dict[str, str]) -> str:
    return (
        str((profile.get("google_oauth") or {}).get("email") or "").strip()
        or str((profile.get("microsoft_oauth") or {}).get("email") or "").strip()
        or str(settings.get("IMAP_USER") or "").strip()
        or str(profile.get("email") or "").strip()
    )


def default_sender_email(profile: Dict[str, Any], settings: Dict[str, str]) -> str:
    return (
        str(settings.get("SMTP_USER") or "").strip()
        or str(settings.get("IMAP_USER") or "").strip()
        or str((profile.get("google_oauth") or {}).get("email") or "").strip()
        or str((profile.get("microsoft_oauth") or {}).get("email") or "").strip()
        or str(profile.get("email") or "").strip()
    )


def get_report_sender_config() -> Dict[str, Any]:
    from_email = (
        get_app_config_value("EMAIL_SUMMARIZER_REPORT_FROM_EMAIL")
        or get_app_config_value("EMAIL_SUMMARIZER_REPORT_SMTP_USER")
        or "discereresearch@gmail.com"
    ).strip()
    smtp_user = (
        get_app_config_value("EMAIL_SUMMARIZER_REPORT_SMTP_USER")
        or get_app_config_value("EMAIL_SUMMARIZER_REPORT_FROM_EMAIL")
        or from_email
    ).strip()
    raw_port = get_app_config_value("EMAIL_SUMMARIZER_REPORT_SMTP_PORT") or "465"
    try:
        smtp_port = int(raw_port)
    except ValueError:
        smtp_port = 465
    return {
        "host": (get_app_config_value("EMAIL_SUMMARIZER_REPORT_SMTP_HOST") or "smtp.gmail.com").strip(),
        "port": smtp_port,
        "user": smtp_user,
        "password": get_app_config_value("EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD").strip(),
        "from_email": from_email,
        "from_name": (get_app_config_value("EMAIL_SUMMARIZER_REPORT_FROM_NAME") or "Discere").strip(),
        "reply_to_email": (
            get_app_config_value("EMAIL_SUMMARIZER_REPORT_REPLY_TO_EMAIL")
            or get_app_config_value("EMAIL_SUMMARIZER_SUPPORT_EMAIL")
            or from_email
        ).strip(),
    }


def get_report_email_mode(settings: Dict[str, str]) -> str:
    return normalize_report_email_mode(settings.get("REPORT_EMAIL_MODE", REPORT_EMAIL_MODE_FULL))


def scheduled_report_email_subject(schedule_name: Any) -> str:
    name = str(schedule_name or "").strip()
    if not name or name.lower() == "scheduled report":
        return SCHEDULED_REPORT_EMAIL_FALLBACK_SUBJECT
    return f"{name} - Scheduled Email Summary"


def smtp_tls_mode_for_port(port: int) -> str:
    return "starttls" if int(port or 0) == 587 else "ssl"


def classify_smtp_delivery_exception(exc: Exception) -> Dict[str, Any]:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return {
            "code": "smtp_auth_failed",
            "status_code": 500,
            "message": "Discere report email delivery needs attention. Please contact Discere support.",
        }
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return {
            "code": "smtp_sender_refused",
            "status_code": 500,
            "message": "Discere report email delivery needs attention. Please contact Discere support.",
        }
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return {
            "code": "smtp_recipient_refused",
            "status_code": 400,
            "message": "The recipient email was rejected by the email provider. Check that your connected account email is valid.",
        }
    if isinstance(exc, smtplib.SMTPDataError):
        return {
            "code": "smtp_message_rejected",
            "status_code": 502,
            "message": "The email provider rejected the report message. Try again later or contact Discere support.",
        }
    if isinstance(exc, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout, TimeoutError)):
        return {
            "code": "smtp_connection_failed",
            "status_code": 502,
            "message": "Discere could not reach the report email provider. This may be temporary; try again shortly.",
        }
    return {
        "code": "smtp_delivery_failed",
        "status_code": 502,
        "message": "Discere report email delivery needs attention. Please contact Discere support.",
    }


def safe_smtp_exception_metadata(exc: Exception) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"error_type": exc.__class__.__name__}
    if isinstance(exc, smtplib.SMTPResponseException):
        metadata["smtp_code"] = int(exc.smtp_code)
    return metadata


def dashboard_url() -> str:
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL}/dashboard"
    return "/dashboard"


def settings_url() -> str:
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL}/settings"
    return "/settings"


def email_logo_url() -> str:
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL}/dashboard_static/discere-logo.png"
    return ""


def render_email_brand_header(title: str, intro: str) -> str:
    logo_url = email_logo_url()
    logo_html = (
        f"<img src='{escape(logo_url)}' alt='Discere' width='42' height='42' "
        "style='display:block; width:42px; height:42px; border:0; outline:none; text-decoration:none; object-fit:contain;'>"
        if logo_url
        else ""
    )
    return (
        "<div style='margin:0 0 22px 0; padding:0 0 18px 0; border-bottom:1px solid #e6e2da;'>"
        "<table role='presentation' cellpadding='0' cellspacing='0' style='border-collapse:collapse; margin:0 0 10px 0;'>"
        "<tr>"
        f"<td style='vertical-align:middle; padding:0 10px 0 0;'>{logo_html}</td>"
        "<td style='vertical-align:middle;'>"
        "<p style='margin:0; color:#6f6d66; font-size:13px; letter-spacing:0.18em; text-transform:uppercase; font-weight:700;'>Discere</p>"
        "</td>"
        "</tr>"
        "</table>"
        f"<h1 style='margin:0; color:#111; font-size:30px; line-height:1.08; letter-spacing:-0.05em;'>{escape(title or 'Discere Email Summary')}</h1>"
        f"<p style='margin:12px 0 0 0; color:#555; font-size:15px; line-height:1.6;'>{escape(intro)}</p>"
        "</div>"
    )


def append_report_email_footer_html(html_body: str, *, support_email: str, include_manage_link: bool = False) -> str:
    support = escape(str(support_email or "").strip())
    manage_link = escape(settings_url())
    manage_html = (
        f"<br>Manage scheduled summaries in <a href='{manage_link}' style='color:#111; font-weight:700;'>Discere settings</a>."
        if include_manage_link
        else ""
    )
    footer = (
        "<div style='margin-top:28px; padding-top:16px; border-top:1px solid #e5e5e5; "
        "color:#6b6b66; font-size:13px; line-height:1.5;'>"
        "You received this because you requested or scheduled a Discere email summary."
        f"{manage_html}"
        f"<br>Need help? Contact <a href='mailto:{support}' style='color:#111; font-weight:700;'>{support}</a>."
        "</div>"
    )
    if "</body>" in html_body:
        return html_body.replace("</body>", f"{footer}</body>", 1)
    return f"{html_body}{footer}"


def append_report_email_footer_text(text_body: str, *, support_email: str, include_manage_link: bool = False) -> str:
    lines = [
        str(text_body or "").strip(),
        "",
        "---",
        "You received this because you requested or scheduled a Discere email summary.",
    ]
    if include_manage_link:
        lines.append(f"Manage scheduled summaries in Discere settings: {settings_url()}")
    if support_email:
        lines.append(f"Need help? Contact {support_email}")
    return "\n".join(line for line in lines if line is not None).strip()


def render_private_report_notification_html(report_label: str = "report") -> str:
    link = dashboard_url()
    link_html = (
        f"<p style='margin:20px 0 0 0;'>"
        f"<a href='{escape(link)}' style='display:inline-block; background:#111; color:#fff; text-decoration:none; "
        f"border-radius:14px; padding:12px 18px; font-weight:700;'>Open Discere</a>"
        f"</p>"
        if link.startswith("http")
        else ""
    )
    return (
        "<html><body style='margin:0; padding:0; background:#ffffff;'>"
        "<div style='font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; color:#111; "
        "max-width:640px; margin:0 auto; padding:24px; background:#fff;'>"
        + render_email_brand_header(
            f"Your Discere {report_label} is ready",
            "Open Discere to read the report inside your dashboard.",
        )
        + "<p style='margin:0; color:#555; line-height:1.6;'>"
        "You chose Email Notification mode, so this email does not include summary content. "
        "Open Discere to read the report inside your dashboard."
        "</p>"
        f"{link_html}"
        "<p style='margin:24px 0 0 0; color:#777; font-size:13px; line-height:1.5;'>"
        "This notification was sent by Discere to your connected account email because you requested or scheduled a report."
        "</p>"
        "</div></body></html>"
    )


def render_private_report_notification_text(report_label: str = "report") -> str:
    lines = [
        f"Your Discere {report_label} is ready.",
        "",
        "You chose Email Notification mode, so this email does not include summary content.",
        "Open Discere to read the report inside your dashboard.",
    ]
    link = dashboard_url()
    if link.startswith("http"):
        lines.extend(["", f"Open Discere: {link}"])
    lines.extend([
        "",
        "This notification was sent by Discere to your connected account email because you requested or scheduled a report.",
    ])
    return "\n".join(lines)


def send_report_email_from_discere(
    user_id: str,
    recipient: str,
    subject: str,
    html_body: str,
    text_body: str,
    event_name: str,
    include_manage_link: bool = False,
) -> Dict[str, str]:
    if not is_valid_email(recipient):
        raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")

    sender = get_report_sender_config()
    if not all([sender["host"], sender["user"], sender["password"], sender["from_email"]]):
        write_monitoring_event(
            "report_delivery",
            "discere_report_sender_not_configured",
            "warning",
            user_id=user_id,
            metadata={
                "smtp_host_configured": bool(sender["host"]),
                "smtp_user_configured": bool(sender["user"]),
                "smtp_password_configured": bool(sender["password"]),
                "from_email_configured": bool(sender["from_email"]),
            },
        )
        raise HTTPException(
            status_code=400,
            detail={
                "code": "report_sender_not_configured",
                "message": "Discere report email delivery needs attention. Please contact Discere support.",
            },
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = formataddr((sender["from_name"], sender["from_email"]))
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=False)
    message_id_domain = sender["from_email"].split("@", 1)[1] if "@" in sender["from_email"] else None
    msg["Message-ID"] = make_msgid(domain=message_id_domain)
    if sender.get("reply_to_email"):
        msg["Reply-To"] = formataddr((sender["from_name"], sender["reply_to_email"]))
    if include_manage_link and settings_url().startswith("http"):
        support_email = sender.get("reply_to_email") or sender["from_email"]
        msg["List-Unsubscribe"] = f"<mailto:{support_email}?subject=Unsubscribe%20Discere%20scheduled%20summaries>, <{settings_url()}>"

    support_email = sender.get("reply_to_email") or sender["from_email"]
    html_with_footer = append_report_email_footer_html(
        html_body,
        support_email=support_email,
        include_manage_link=include_manage_link,
    )
    text_with_footer = append_report_email_footer_text(
        text_body,
        support_email=support_email,
        include_manage_link=include_manage_link,
    )
    msg.attach(MIMEText(_to_ascii_safe(text_with_footer), "plain", "utf-8"))
    msg.attach(MIMEText(html_with_footer, "html", "utf-8"))

    try:
        if sender["port"] == 587:
            with smtplib.SMTP(sender["host"], sender["port"], timeout=30) as server:
                server.starttls()
                server.login(sender["user"], sender["password"])
                server.sendmail(sender["from_email"], [recipient], msg.as_string())
        else:
            with smtplib.SMTP_SSL(sender["host"], sender["port"], timeout=30) as server:
                server.login(sender["user"], sender["password"])
                server.sendmail(sender["from_email"], [recipient], msg.as_string())
    except Exception as exc:
        failure = classify_smtp_delivery_exception(exc)
        write_monitoring_event(
            "report_delivery",
            event_name,
            "error",
            user_id=user_id,
            metadata={
                "recipient": recipient,
                "smtp_host": sender["host"],
                "smtp_port": sender["port"],
                "smtp_tls_mode": smtp_tls_mode_for_port(sender["port"]),
                "smtp_user": sender["user"],
                "from_email": sender["from_email"],
                "failure_code": failure["code"],
                **safe_smtp_exception_metadata(exc),
            },
        )
        raise HTTPException(
            status_code=int(failure["status_code"]),
            detail={"code": failure["code"], "message": failure["message"]},
        ) from exc

    return {"recipient": recipient, "subject": subject, "from": sender["from_email"]}


def send_summary_via_smtp(user_id: str, summary: Dict[str, Any]) -> Dict[str, str]:
    settings = get_settings_for_user(user_id)
    profile = load_profile(user_id) or {}
    recipient = default_report_recipient(profile, settings)

    if not is_valid_email(recipient):
        raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")

    report_email_mode = get_report_email_mode(settings)
    if report_email_mode == REPORT_EMAIL_MODE_PRIVATE:
        return send_report_email_from_discere(
            user_id=user_id,
            recipient=recipient,
            subject=MANUAL_REPORT_EMAIL_SUBJECT,
            html_body=render_private_report_notification_html("summary"),
            text_body=render_private_report_notification_text("summary"),
            event_name="discere_summary_email_failed",
        )

    html_body = render_summary_email_html(summary)
    return send_report_email_from_discere(
        user_id=user_id,
        recipient=recipient,
        subject=MANUAL_REPORT_EMAIL_SUBJECT,
        html_body=html_body,
        text_body=render_report_email_text("Discere Email Summary", [summary_to_report_card(summary)], max_chars=20000),
        event_name="discere_summary_email_failed",
    )


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

        executive_summary = str(summary.get("executive_summary", "") or "").strip()
        if executive_summary:
            parts.append(executive_summary)
        else:
            parts.append("No executive summary is available for this summary.")

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
        "title": f"Selected Summary Report ({len(summaries)} Selected)",
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
    return render_report_email_html(
        title or "Discere Email Summary",
        parse_report_markdown_cards(markdown),
        intro="Here are your latest summaries.",
    )


def send_combined_report_via_smtp(
    user_id: str,
    title: str,
    markdown: str,
    subject: str = MANUAL_REPORT_EMAIL_SUBJECT,
) -> Dict[str, str]:
    settings = get_settings_for_user(user_id)
    profile = load_profile(user_id) or {}
    recipient = default_report_recipient(profile, settings)

    if not is_valid_email(recipient):
        raise HTTPException(status_code=400, detail="A valid recipient email is required before sending.")

    report_email_mode = get_report_email_mode(settings)
    if report_email_mode == REPORT_EMAIL_MODE_PRIVATE:
        delivery = send_report_email_from_discere(
            user_id=user_id,
            recipient=recipient,
            subject=subject,
            html_body=render_private_report_notification_html("report"),
            text_body=render_private_report_notification_text("report"),
            event_name="discere_combined_report_email_failed",
            include_manage_link=subject != MANUAL_REPORT_EMAIL_SUBJECT,
        )
    else:
        html_body = render_markdown_report_email_html(title, markdown)
        delivery = send_report_email_from_discere(
            user_id=user_id,
            recipient=recipient,
            subject=subject,
            html_body=html_body,
            text_body=render_markdown_report_text(title, markdown, max_chars=20000),
            event_name="discere_combined_report_email_failed",
            include_manage_link=subject != MANUAL_REPORT_EMAIL_SUBJECT,
        )

    track_analytics_event(
        user_id,
        "report_delivered",
        {"delivery_channel": "email", "recipient": recipient, "title": title, "report_email_mode": report_email_mode},
    )
    return delivery


def render_markdown_report_text(title: str, markdown: str, max_chars: int = 1400) -> str:
    return render_report_email_text(
        title or "Discere Email Summary",
        parse_report_markdown_cards(markdown),
        max_chars=max_chars,
    )


def paragraph_markup(text: str) -> str:
    escaped = escape(clean_markdown_heading_text(str(text or "")))
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

    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#6f6d66"),
        spaceAfter=8,
    )

    story: List[Any] = [Paragraph(paragraph_markup(title), title_style), Spacer(1, 0.08 * inch)]
    cards = parse_report_markdown_cards(markdown)
    if not cards:
        cards = [{"title": "Report", "email": "", "updated_at": "", "sections": {"Report": markdown}}]

    for card_index, card in enumerate(cards):
        if card_index:
            story.append(Spacer(1, 0.12 * inch))
        story.append(Paragraph(paragraph_markup(str(card.get("title") or "Summary")), heading_style))
        meta_parts = []
        if card.get("email") and card.get("email") != card.get("title"):
            meta_parts.append(str(card["email"]))
        if card.get("updated_at"):
            meta_parts.append(f"Updated: {card['updated_at']}")
        if meta_parts:
            story.append(Paragraph(paragraph_markup(" | ".join(meta_parts)), meta_style))

        sections = card.get("sections") or {}
        ordered_labels = [label for label in REPORT_SECTION_ORDER if str(sections.get(label, "")).strip()]
        ordered_labels.extend(label for label in sections if label not in ordered_labels and str(sections.get(label, "")).strip())
        for section_title in ordered_labels:
            lines = [clean_markdown_heading_text(line.strip()) for line in str(sections.get(section_title, "") or "").splitlines() if line.strip()]
            if not lines:
                continue
            story.append(Paragraph(paragraph_markup(section_title), heading_style))
            bullet_lines = []
            plain_lines = []
            for line in lines:
                bullet_match = re.match(r"^(?:[-*•]\s+)(.+)$", line)
                if bullet_match:
                    bullet_lines.append(bullet_match.group(1).strip())
                else:
                    plain_lines.append(line)
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


def sms_delivery_enabled() -> bool:
    return os.getenv("EMAIL_SUMMARIZER_SMS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def send_text_via_twilio(phone_number: str, body: str, media_url: Optional[str] = None) -> Dict[str, str]:
    if not sms_delivery_enabled():
        raise HTTPException(status_code=404, detail="SMS delivery is not available.")
    account_sid = get_app_config_value("TWILIO_ACCOUNT_SID")
    auth_token = get_app_config_value("TWILIO_AUTH_TOKEN")
    from_number = get_app_config_value("TWILIO_FROM_NUMBER")
    messaging_service_sid = get_app_config_value("TWILIO_MESSAGING_SERVICE_SID")

    if not account_sid or not auth_token:
        raise HTTPException(status_code=500, detail="SMS delivery is not configured.")
    if not from_number and not messaging_service_sid:
        raise HTTPException(status_code=500, detail="SMS delivery is not configured.")
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
        write_monitoring_event(
            "report_delivery",
            "twilio_http_error",
            "error",
            metadata={"phone_number": phone_number, "status_code": exc.code, "response": payload_text[:1200]},
        )
        raise HTTPException(status_code=500, detail="SMS delivery failed.") from exc
    except Exception as exc:
        write_monitoring_event(
            "report_delivery",
            "twilio_send_failed",
            "error",
            metadata={"phone_number": phone_number, "error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise HTTPException(status_code=500, detail="SMS delivery failed.") from exc

    return {
        "recipient_phone": phone_number,
        "message_sid": str(response_payload.get("sid", "")),
        "delivery_channel": "sms",
    }


def send_combined_report_via_sms(user_id: str, title: str, markdown: str, phone_number: str) -> Dict[str, Any]:
    try:
        pdf_path = generate_report_pdf(user_id, title, markdown)
        public_pdf_url = build_public_report_url(user_id, pdf_path)
        message_body = render_markdown_report_text(title, markdown, max_chars=240) + f"\n\nOpen PDF: {public_pdf_url}"
        media_url = public_pdf_url if should_attach_pdf_to_message(pdf_path) else None
        delivery = send_text_via_twilio(phone_number, message_body, media_url=media_url)
    except Exception as exc:
        write_monitoring_event(
            "report_delivery",
            "sms_report_delivery_failed",
            "error",
            user_id=user_id,
            metadata={"phone_number": phone_number, "title": title, "error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise
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


def advance_report_schedule(schedule: sqlite3.Row) -> None:
    timezone_name = str(schedule["timezone"] or "America/Los_Angeles")
    now_dt = datetime.now(ZoneInfo(timezone_name))
    next_run_at = compute_next_schedule_run(
        now=now_dt,
        timezone_name=timezone_name,
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
            (now_dt.isoformat(), next_run_at, datetime.now().isoformat(), str(schedule["schedule_id"])),
        )


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
        if not get_contacts_for_user(user_id):
            write_monitoring_event(
                "scheduled_report",
                "scheduled_report_skipped_no_contacts",
                "info",
                user_id=user_id,
                metadata={"schedule_id": schedule_id},
            )
            advance_report_schedule(schedule)
            return

        try:
            enforce_subscription_access(user_id, "scheduled_report")
            enforce_usage_limit(user_id, "scheduled_report")
        except HTTPException:
            advance_report_schedule(schedule)
            return

        run_result = execute_summarizer_run(user_id, days_back)
        summaries = (
            load_summaries_by_ids_for_user(user_id, run_result.get("new_summary_ids") or [])
            if run_result.get("success")
            else []
        )
        if summaries:
            markdown = build_scheduled_report_markdown(summaries)
            title = str(schedule["name"] or "Scheduled Report").strip() or "Scheduled Report"
            send_combined_report_via_smtp(
                user_id,
                title,
                markdown,
                subject=scheduled_report_email_subject(title),
            )

        advance_report_schedule(schedule)
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


# PUBLIC SITE CHAT WIDGET ENDPOINT
# Remove this block plus dashboard_static/public_chat_widget.{js,css} and the two page includes
# if the public education chatbot is removed later.
@app.post("/public-chat")
def public_chat(payload: PublicChatRequest, request: Request) -> Dict[str, Any]:
    question = enforce_text_limit(payload.question, "Question", MAX_PUBLIC_CHAT_QUESTION_CHARS)
    if not question:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        write_monitoring_event("server_error", "openai_key_missing_public_chat", "error", request=request)
        raise HTTPException(status_code=500, detail="Ask Discere is temporarily unavailable. Please try again later.")

    model = normalize_openai_model(os.getenv("OPENAI_MODEL") or "gpt-5.1")
    recent_history = build_public_chat_history(payload.conversation)
    instructions = (
        "You are Ask Discere, a public website assistant for Discere. "
        "Answer only questions about what Discere does, how to use it, privacy/security basics, Gmail/Microsoft login, reports, schedules, trial/pricing, and account deletion. "
        "You cannot access the visitor's account, inbox, summaries, contacts, schedules, or billing status. Say that clearly if asked. "
        "Write for busy adults age 40+ who may not follow new AI tools. Use simple words, short sentences, and concrete steps. "
        "Be concise: usually 2-5 short sentences. Use bullets only when steps are useful. "
        "Do not use markdown formatting. Do not use # headings, asterisks, bold markers, code fences, or markdown bullet symbols. "
        "If steps are needed, write simple numbered lines like '1. Log in with Gmail or Microsoft.' "
        "Do not use jargon like OAuth unless the user asks; say 'secure Google/Microsoft sign-in' instead. "
        "Do not provide legal, medical, financial, or security advice. For sensitive business decisions, suggest reviewing Privacy/Security pages or contacting Discere support. "
        "If a question is unrelated to Discere, briefly say you can help with Discere questions."
    )
    input_text = (
        "DISCERE PUBLIC KNOWLEDGE\n"
        f"{PUBLIC_DISCERE_CHAT_KNOWLEDGE}\n\n"
        "RECENT WEBSITE CHAT HISTORY\n"
        f"{recent_history or '[No prior chat history]'}\n\n"
        "VISITOR QUESTION\n"
        f"{_to_ascii_safe(question)}\n"
    )

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=model,
            instructions=instructions,
            input=input_text,
            temperature=0.1,
            max_output_tokens=420,
        )
    except Exception as exc:
        write_monitoring_event(
            "server_error",
            "openai_public_chat_failed",
            "error",
            request=request,
            metadata={"model": model, "error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise HTTPException(status_code=500, detail="Ask Discere could not answer right now. Please try again shortly.") from exc

    answer = clean_chat_answer_text(str(getattr(response, "output_text", "") or ""))
    if not answer:
        answer = "I could not answer that clearly. Try asking in a simpler way, or contact support@discere-ai.com."

    return {"answer": answer}


@app.post("/chat")
def chat(payload: ChatRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    enforce_subscription_access(resolved_user_id, "chat")
    enforce_usage_limit(resolved_user_id, "chat")
    question = enforce_text_limit(payload.question, "Question", MAX_CHAT_QUESTION_CHARS)
    if not question:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    summaries = get_chat_ready_summaries(resolved_user_id)
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
        write_monitoring_event("server_error", "openai_key_missing_chat", "error", request=request, user_id=resolved_user_id)
        raise HTTPException(status_code=500, detail="AI Assistant needs attention. Please contact Discere support.")

    client = OpenAI(api_key=api_key)
    context = build_chat_context(resolved_user_id, summaries, emails)
    recent_history = build_recent_chat_history(payload.conversation)
    instructions = (
        "You are Discere's grounded AI assistant. You answer questions about the user's historical email summaries/source emails "
        "and questions about how Discere works, including privacy, security, terms, OAuth, retention, schedules, reports, and settings. "
        "Address the user as 'you' rather than by name. "
        "For email-specific questions, answer only from the provided summaries and email bodies. Do not invent facts, deadlines, requests, attachments, or email text. "
        "For Discere product, privacy, security, terms, and workflow questions, answer only from the Discere product knowledge provided. "
        "If there are no saved summaries yet, do not mention the internal user ID. For email-specific questions, briefly say there are no saved summaries yet and explain the next step: add contacts, run the summarizer, then ask again. "
        "If the answer is not in the provided context or product knowledge, say so clearly and suggest checking Settings, Privacy, Security FAQ, Terms, or contacting support@discere-ai.com. "
        "If the user asks where something was said, quote the exact relevant email text when available. "
        "If the user asks about attachments, mention attachment filenames explicitly when available. "
        "If the user asks why deleted summaries/emails appear again, explain that deleting a summary removes the identifier so it can be rediscovered; marking it done keeps the identifier so it should not be re-summarized accidentally. "
        "Prefer practical, concise answers. Use short paragraphs or simple numbered steps. Do not use markdown formatting, # headings, asterisks, code fences, or dense blocks of text."
    )
    input_text = (
        "DISCERE PRODUCT KNOWLEDGE\n"
        f"{DISCERE_PRODUCT_KNOWLEDGE}\n\n"
        "RECENT CHAT HISTORY\n"
        f"{recent_history or '[No prior chat history provided]'}\n\n"
        "USER EMAIL SUMMARY CONTEXT\n"
        f"{context or '[No saved summaries yet. The assistant should still answer Discere how-to questions from product knowledge.]'}\n\n"
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
        write_monitoring_event(
            "server_error",
            "openai_chat_failed",
            "error",
            request=request,
            user_id=resolved_user_id,
            metadata={"model": model, "error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise HTTPException(status_code=500, detail="AI Assistant could not answer right now. Please try again shortly.") from exc

    return {
        "user_id": resolved_user_id,
        "answer": clean_chat_answer_text(response.output_text),
        "summary_count": len(summaries),
        "email_count": len(emails),
        "attachment_matches": attachment_matches,
    }


@app.post("/summaries/combined")
def combined_summary(payload: CombinedSummaryRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    enforce_subscription_access(resolved_user_id, "combined_summary")
    enforce_summary_id_limit(payload.summary_ids)
    return generate_combined_summary_content(resolved_user_id, payload.summary_ids, request)


@app.post("/summaries/combined/send-email")
def send_combined_summary_email(payload: CombinedSummaryRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    enforce_subscription_access(resolved_user_id, "report_delivery")
    enforce_summary_id_limit(payload.summary_ids)
    enforce_usage_limit(resolved_user_id, "report_delivery")
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
    if not sms_delivery_enabled():
        raise HTTPException(status_code=404, detail="SMS delivery is not available.")
    enforce_subscription_access(resolved_user_id, "report_delivery")
    enforce_summary_id_limit(payload.summary_ids)
    enforce_usage_limit(resolved_user_id, "report_delivery")
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
    enforce_subscription_access(resolved_user_id, "refine")
    enforce_usage_limit(resolved_user_id, "refine")
    markdown = enforce_text_limit(payload.markdown, "Summary content", MAX_REFINE_MARKDOWN_CHARS)
    instructions = enforce_text_limit(payload.instructions, "Refinement instructions", MAX_REFINE_INSTRUCTIONS_CHARS)
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
        write_monitoring_event("server_error", "openai_key_missing_refine", "error", request=request, user_id=resolved_user_id)
        raise HTTPException(status_code=500, detail="Summary refinement needs attention. Please contact Discere support.")

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
        write_monitoring_event(
            "server_error",
            "openai_refine_failed",
            "error",
            request=request,
            user_id=resolved_user_id,
            metadata={"model": model, "error": str(exc), "error_type": exc.__class__.__name__},
        )
        raise HTTPException(status_code=500, detail="Discere could not refine the summary right now. Please try again shortly.") from exc

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


@app.post("/summaries/refine-selected")
def refine_selected_summaries(payload: RefineSelectedSummariesRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    enforce_subscription_access(resolved_user_id, "refine")
    enforce_usage_limit(resolved_user_id, "refine")
    enforce_summary_id_limit(payload.summary_ids)
    instructions = enforce_text_limit(payload.instructions, "Refinement instructions", MAX_REFINE_INSTRUCTIONS_CHARS)
    if not instructions:
        raise HTTPException(status_code=400, detail="Refinement instructions cannot be empty.")

    cleaned_summary_ids = [summary_id.strip() for summary_id in payload.summary_ids if summary_id.strip()]
    if not cleaned_summary_ids:
        raise HTTPException(status_code=400, detail="Select at least one summary first.")

    settings = get_settings_for_user(resolved_user_id)
    api_key = settings.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    model = normalize_openai_model(settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.1")
    saved_preferences = parse_summary_style_preferences(settings)
    if not api_key:
        write_monitoring_event("server_error", "openai_key_missing_refine_selected", "error", request=request, user_id=resolved_user_id)
        raise HTTPException(status_code=500, detail="Summary refinement needs attention. Please contact Discere support.")

    instructions_text = (
        "You are refining saved email summaries for one user. "
        "Keep each output grounded in that summary's provided content only. "
        "Do not add new facts, deadlines, people, or attachments. "
        "Follow the user's refinement request closely. "
        + (
            "The user also has saved summary style preferences. Apply them unless the current refinement request conflicts:\n"
            + "\n".join(f"- {item}" for item in saved_preferences)
            + "\n"
            if saved_preferences else ""
        )
        + (
            "Return Markdown. Preserve clear sections such as Executive Summary, Main Topics, Action Items / Asks, "
            "Deadlines / Dates / Meetings, Attachment Summary, and Bottom Line when those sections are useful."
        )
    )

    client = OpenAI(api_key=api_key)
    refined_summaries: List[Dict[str, Any]] = []
    skipped_summary_ids: List[str] = []
    json_summaries_dir = get_user_json_summaries_dir(resolved_user_id)

    for summary_id in cleaned_summary_ids:
        summary_path = safe_user_file_path(json_summaries_dir, summary_id, ".json", "summary id")
        if not summary_path.exists():
            skipped_summary_ids.append(summary_id)
            continue

        summary = load_summary_json(summary_path)
        markdown = enforce_text_limit(
            build_markdown_from_summary_payload(summary),
            "Summary content",
            MAX_REFINE_MARKDOWN_CHARS,
        )
        if not markdown:
            skipped_summary_ids.append(summary_id)
            continue

        title = str(summary.get("title") or summary.get("summary_id") or "Summary").strip()
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
            write_monitoring_event(
                "server_error",
                "openai_refine_selected_failed",
                "error",
                request=request,
                user_id=resolved_user_id,
                metadata={"model": model, "summary_id": summary_id, "error": str(exc), "error_type": exc.__class__.__name__},
            )
            raise HTTPException(status_code=500, detail="Discere could not refine the summary right now. Please try again shortly.") from exc

        updated_summary = apply_refined_markdown_to_summary(summary, response.output_text)
        save_summary_json(summary_path, updated_summary)
        refined_summaries.append(
            {
                "summary_id": summary_id,
                "title": updated_summary.get("title", title),
                "refined_markdown": updated_summary.get("summary_markdown", ""),
            }
        )

    if not refined_summaries:
        raise HTTPException(status_code=404, detail="None of the selected summaries could be refined.")

    updated_preferences = saved_preferences
    if payload.save_preference:
        updated_preferences = add_summary_style_preference(resolved_user_id, instructions)

    track_analytics_event(
        resolved_user_id,
        "refinement_used",
        {
            "summary_count": len(refined_summaries),
            "instruction_length": len(instructions),
            "saved_preference": bool(payload.save_preference),
        },
    )

    return {
        "success": True,
        "user_id": resolved_user_id,
        "count": len(refined_summaries),
        "summary_ids": [item["summary_id"] for item in refined_summaries],
        "skipped_summary_ids": skipped_summary_ids,
        "summaries": refined_summaries,
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
    title = enforce_text_limit(payload.title, "Bug title", MAX_BUG_TITLE_CHARS)
    description = enforce_text_limit(payload.description, "Bug description", MAX_BUG_DESCRIPTION_CHARS)
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


def sanitize_summarizer_public_error(raw_output: str, parsed_error: str = "") -> str:
    combined = f"{raw_output or ''}\n{parsed_error or ''}"
    lower = combined.lower()
    if is_microsoft_reconnect_error_text(combined):
        return MICROSOFT_RECONNECT_MESSAGE
    if "google" in lower and any(
        token in lower
        for token in [
            "invalid credentials",
            "insufficient authentication scopes",
            "access_token_scope_insufficient",
            "http error 401",
            "http error 403",
        ]
    ):
        return "Google mailbox access expired or needs permission again. Please reconnect Google, then try again."
    if any(token in lower for token in ["mailbox is not connected", "missing imap credentials", "missing mailbox credentials"]):
        return "Mailbox connection is not ready. Contact Discere support to finish the private mailbox setup."
    if "usage limit" in lower or "daily usage limit" in lower:
        return "Daily usage limit reached. Try again tomorrow."
    if "openai" in lower:
        return "Discere could not generate the summary right now. Please try again shortly."
    return GENERIC_SUMMARIZER_ERROR_MESSAGE


def execute_summarizer_run(user_id: str, days_back: int) -> Dict[str, Any]:
    profile = load_profile_or_404(user_id)
    try:
        ensure_mailbox_access_ready(profile, user_id, refresh_oauth=True)
    except HTTPException as exc:
        detail = str(exc.detail or "Mailbox access is not ready.")
        result = {
            "returncode": 1,
            "stdout": "",
            "stderr": detail,
            "message": detail,
            "stats": {},
            "success": False,
        }
        if is_microsoft_reconnect_error_text(detail):
            result["message"] = MICROSOFT_RECONNECT_MESSAGE
            result["stderr"] = MICROSOFT_RECONNECT_MESSAGE
            result["reconnect_provider"] = "microsoft"
            result["reconnect_url"] = microsoft_reconnect_url(profile)
        return result

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
    parsed_error = ""
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
        if isinstance(parsed_payload, dict) and parsed_payload.get("success") is False:
            parsed_error = str(parsed_payload.get("error") or "").strip()
            break

    raw_stdout = result.stdout[-4000:]
    raw_stderr = result.stderr[-4000:]
    safe_stdout = truncate_monitoring_value(raw_stdout, 4000)
    safe_stderr = truncate_monitoring_value(raw_stderr, 4000)
    public_error = sanitize_summarizer_public_error(f"{raw_stderr}\n{raw_stdout}", parsed_error) if result.returncode != 0 else ""
    reconnect_provider = ""
    reconnect_url = ""
    combined_output = f"{raw_stderr}\n{raw_stdout}\n{parsed_error}"
    if is_microsoft_reconnect_error_text(combined_output):
        reconnect_provider = "microsoft"
        reconnect_url = microsoft_reconnect_url(profile)

    result_payload = {
        "returncode": result.returncode,
        "stdout": "",
        "stderr": public_error,
        "stats": parsed_stats,
        "success": result.returncode == 0,
    }
    if public_error:
        result_payload["message"] = public_error
    if reconnect_provider and reconnect_url:
        result_payload["reconnect_provider"] = reconnect_provider
        result_payload["reconnect_url"] = reconnect_url
    if result_payload["success"]:
        result_payload["new_summary_ids"] = load_last_run_summary_ids_for_user(user_id)
    after_count = len(load_all_current_summaries_for_user(user_id))
    if result_payload["success"] and before_count == 0 and after_count > 0 and not analytics_event_exists(user_id, "first_summary_generated"):
        track_analytics_event(
            user_id,
            "first_summary_generated",
            {"days_back": days_back, "summary_count": after_count},
        )
    if not result_payload["success"]:
        monitoring_output = combined_output
        category = "summarizer"
        event_name = "summarizer_failed"
        if "gmail" in monitoring_output.lower() or "imap" in monitoring_output.lower() or "oauth" in monitoring_output.lower() or "token" in monitoring_output.lower() or "microsoft graph" in monitoring_output.lower():
            event_name = "summarizer_mailbox_or_oauth_failed"
        if "openai" in monitoring_output.lower():
            event_name = "summarizer_openai_failed"
        write_monitoring_event(
            category,
            event_name,
            "error",
            user_id=user_id,
            metadata={
                "days_back": days_back,
                "returncode": result_payload.get("returncode"),
                "stderr_tail": safe_stderr[-1200:],
                "stdout_tail": safe_stdout[-1200:],
                "public_error": public_error,
            },
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
            write_monitoring_event(
                "summarizer",
                "summarizer_timeout",
                "error",
                user_id=user_id,
                metadata={"job_id": job_id, "days_back": days_back, "timeout_seconds": 600},
            )
            final_job = {
                "job_id": job_id,
                "user_id": user_id,
                "days_back": days_back,
                "status": "failed",
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "returncode": None,
                "stdout": "",
                "stderr": "Discere could not finish the email check before it timed out. Please try again.",
                "message": "Discere could not finish the email check before it timed out. Please try again.",
                "stats": {},
                "success": False,
            }
        except Exception as exc:
            write_monitoring_event(
                "summarizer",
                "summarizer_worker_exception",
                "critical",
                user_id=user_id,
                metadata={"job_id": job_id, "days_back": days_back, "error": str(exc), "error_type": exc.__class__.__name__},
            )
            final_job = {
                "job_id": job_id,
                "user_id": user_id,
                "days_back": days_back,
                "status": "failed",
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "returncode": None,
                "stdout": "",
                "stderr": GENERIC_SUMMARIZER_ERROR_MESSAGE,
                "message": GENERIC_SUMMARIZER_ERROR_MESSAGE,
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
    enforce_subscription_access(resolved_user_id, "run_summarizer")
    profile = load_profile_or_404(resolved_user_id)
    ensure_mailbox_access_ready(profile, resolved_user_id, request=request, refresh_oauth=True)
    enforce_usage_limit(resolved_user_id, "run_summarizer")
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
    json_summary_path = safe_user_file_path(get_user_json_summaries_dir(user_id), summary_id, ".json", "summary id")
    if json_summary_path.exists():
        return apply_contact_profile_to_summary(load_summary_json(json_summary_path), contact_profiles)

    summary_path = safe_user_file_path(get_user_summaries_dir(user_id), summary_id, ".md", "summary id")
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Summary not found.")

    return load_summary_file(summary_path)


@app.get("/summaries/{summary_id}/thread")
def get_summary_thread(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    summary_path = safe_user_file_path(get_user_json_summaries_dir(user_id), summary_id, ".json", "summary id")
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Summary not found.")

    summary = load_summary_json(summary_path)
    email_ids = [str(email_id).strip() for email_id in summary.get("source_email_file_ids", []) or [] if str(email_id).strip()]
    threads: List[Dict[str, Any]] = []
    missing_email_count = 0
    purged_email_count = 0

    for email_id in email_ids:
        email_path = safe_user_file_path(get_user_json_emails_dir(user_id), email_id, ".json", "email id")
        if not email_path.exists():
            missing_email_count += 1
            continue
        email_payload = load_email_json(email_path)
        if email_payload.get("content_purged_at"):
            purged_email_count += 1
            continue
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

    unavailable_reason = ""
    if not threads:
        if purged_email_count:
            unavailable_reason = "Full thread is no longer stored for this summary. Source email bodies are purged after the retention period once a summary is read or done."
        elif missing_email_count or email_ids:
            unavailable_reason = "Full thread is no longer stored for this summary."
        else:
            unavailable_reason = "No saved full thread was found for this summary."

    return {
        "summary_id": summary_id,
        "title": summary.get("title", summary_id),
        "contact_label": summary.get("contact_label", ""),
        "email_record_count": len(threads),
        "content_available": bool(threads),
        "missing_email_count": missing_email_count,
        "purged_email_count": purged_email_count,
        "unavailable_reason": unavailable_reason,
        "threads": threads,
    }


@app.post("/summaries/{summary_id}/mark-read")
def mark_summary_read(summary_id: str, request: Request, user_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    summary_path = safe_user_file_path(get_user_json_summaries_dir(user_id), summary_id, ".json", "summary id")
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Summary not found.")

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
    summary_path = safe_user_file_path(get_user_json_summaries_dir(user_id), summary_id, ".json", "summary id")
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Summary not found.")

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
    enforce_subscription_access(user_id, "report_delivery")
    enforce_usage_limit(user_id, "report_delivery")
    summary = get_summary(summary_id, request, user_id)
    delivery = send_summary_via_smtp(user_id, summary)
    return {
        "success": True,
        "user_id": user_id,
        "summary_id": summary_id,
        **delivery,
    }
