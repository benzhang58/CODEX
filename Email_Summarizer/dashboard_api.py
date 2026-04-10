import json
import os
import re
import hashlib
import hmac
import secrets
import smtplib
import subprocess
import unicodedata
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


app = FastAPI(title="Email Summarizer Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "email_summaries_output"
STATIC_DIR = BASE_DIR / "dashboard_static"
DATA_DIR = BASE_DIR / "data" / "users"
SESSION_COOKIE_NAME = "email_dashboard_session"
SESSION_STORE: Dict[str, Dict[str, str]] = {}
GOOGLE_OAUTH_STATE: Dict[str, Dict[str, str]] = {}
GOOGLE_OAUTH_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]


class RunSummarizerRequest(BaseModel):
    user_id: Optional[str] = None
    days_back: int = 7


class WhitelistUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    contacts: List[str]


class ChatRequest(BaseModel):
    user_id: Optional[str] = None
    question: str


class CombinedSummaryRequest(BaseModel):
    user_id: Optional[str] = None
    summary_ids: List[str]


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


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/dashboard")
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


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
        "&prompt=consent"
        f"&state={quote(state, safe='')}"
    )
    return RedirectResponse(auth_url)


@app.get("/auth/google/callback")
def auth_google_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None) -> RedirectResponse:
    if error:
        return RedirectResponse(f"/dashboard?google_error={quote(error, safe='')}")
    if not code or not state or state not in GOOGLE_OAUTH_STATE:
        return RedirectResponse("/dashboard?google_error=invalid_callback")

    config = get_google_oauth_config()
    next_url = GOOGLE_OAUTH_STATE.pop(state, {}).get("next") or "/dashboard"

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
        return RedirectResponse("/dashboard?google_error=token_exchange_failed")
    access_token = token_payload.get("access_token")
    if not access_token:
        return RedirectResponse("/dashboard?google_error=missing_access_token")

    try:
        userinfo = get_json_with_bearer("https://openidconnect.googleapis.com/v1/userinfo", access_token)
    except HTTPException:
        return RedirectResponse("/dashboard?google_error=userinfo_failed")
    email = str(userinfo.get("email", "")).strip().lower()
    if not email:
        return RedirectResponse("/dashboard?google_error=no_email_returned")

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
    redirect_uri = get_app_config_value("GOOGLE_REDIRECT_URI") or "http://127.0.0.1:8000/auth/google/callback"
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


def post_form_json(url: str, data: Dict[str, str]) -> Dict[str, Any]:
    body = "&".join(f"{quote(str(key), safe='')}={quote(str(value), safe='')}" for key, value in data.items()).encode("utf-8")
    request = UrlRequest(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"Google token exchange failed: {payload}") from exc


def get_json_with_bearer(url: str, access_token: str) -> Dict[str, Any]:
    request = UrlRequest(url, headers={"Authorization": f"Bearer {access_token}"}, method="GET")
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=500, detail=f"Google userinfo request failed: {payload}") from exc


def default_profile_settings() -> Dict[str, str]:
    settings = {
        "OPENAI_API_KEY": "",
        "OPENAI_MODEL": "gpt-4o",
        "WHITELIST_SENDERS": "",
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
        settings.update(read_env_key_values(base_env))
    return settings


def profile_settings_to_response(settings: Dict[str, str]) -> Dict[str, str]:
    return {
        "openai_api_key": settings.get("OPENAI_API_KEY", ""),
        "openai_model": settings.get("OPENAI_MODEL", "gpt-4o"),
        "imap_server": settings.get("IMAP_SERVER", ""),
        "imap_port": settings.get("IMAP_PORT", "993"),
        "imap_user": settings.get("IMAP_USER", ""),
        "imap_password": settings.get("IMAP_PASSWORD", ""),
        "imap_folder": settings.get("IMAP_FOLDER", "INBOX"),
        "smtp_host": settings.get("SMTP_HOST", ""),
        "smtp_port": settings.get("SMTP_PORT", "465"),
        "smtp_user": settings.get("SMTP_USER", ""),
        "smtp_password": settings.get("SMTP_PASSWORD", ""),
        "summary_recipient": settings.get("SUMMARY_RECIPIENT", ""),
    }


def profile_update_to_settings(update: ProfileUpdateRequest, existing: Dict[str, str]) -> Dict[str, str]:
    settings = dict(existing)
    settings.update(
        {
            "IMAP_USER": update.imap_user.strip(),
            "IMAP_PASSWORD": update.imap_password,
        }
    )
    if update.email.strip():
        settings["SUMMARY_RECIPIENT"] = update.email.strip()
        settings["SMTP_USER"] = settings.get("SMTP_USER") or update.email.strip()
    if update.imap_password:
        settings["SMTP_PASSWORD"] = settings.get("SMTP_PASSWORD") or update.imap_password
    return settings


def load_profile(user_id: str) -> Optional[Dict[str, Any]]:
    profile_path = get_profile_path_for_user(user_id)
    if not profile_path.exists():
        return None
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    payload["settings"] = {**default_profile_settings(), **(payload.get("settings") or {})}
    return payload


def find_profile_by_email(email: str) -> Optional[Dict[str, Any]]:
    normalized = email.strip().lower()
    if not normalized:
        return None
    for profile_path in DATA_DIR.glob("*/profile.json"):
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
        if str(payload.get("email", "")).strip().lower() == normalized:
            payload["settings"] = {**default_profile_settings(), **(payload.get("settings") or {})}
            return payload
    return None


def load_profile_or_404(user_id: str) -> Dict[str, Any]:
    profile = load_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No profile found for user '{user_id}'.")
    return profile


def save_profile(profile: Dict[str, Any]) -> None:
    user_id = profile["user_id"]
    user_dir = DATA_DIR / user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    profile["updated_at"] = datetime.now().isoformat()
    (user_dir / "profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")


def profile_response(profile: Dict[str, Any]) -> Dict[str, Any]:
    settings = profile.get("settings") or {}
    contacts = [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
    return {
        "user_id": profile["user_id"],
        "email": profile.get("email", ""),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "contacts": contacts,
        "google_connected": bool((profile.get("google_oauth") or {}).get("refresh_token") or (profile.get("google_oauth") or {}).get("access_token")),
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
    SESSION_STORE[session_token] = {"user_id": user_id, "created_at": datetime.now().isoformat()}
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )
    return session_token


def clear_session(response: Response, request: Request) -> None:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        SESSION_STORE.pop(session_token, None)
    response.delete_cookie(SESSION_COOKIE_NAME)


def get_session_user_id(request: Request) -> Optional[str]:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None
    session_payload = SESSION_STORE.get(session_token)
    if not session_payload:
        return None
    return session_payload.get("user_id")


def resolve_user_id(request: Request, explicit_user_id: Optional[str] = None) -> str:
    if explicit_user_id and explicit_user_id.strip():
        return explicit_user_id.strip()

    session_user_id = get_session_user_id(request)
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
    cleaned_contacts = [contact.strip() for contact in contacts if contact.strip()]
    profile = load_profile(user_id)
    if profile:
        profile["settings"] = {**default_profile_settings(), **(profile.get("settings") or {})}
        profile["settings"]["WHITELIST_SENDERS"] = ",".join(cleaned_contacts)
        save_profile(profile)
        return

    env_path = get_env_path_for_user(user_id)
    write_env_key(env_path, "WHITELIST_SENDERS", ",".join(cleaned_contacts))


@app.get("/users")
def list_available_users() -> Dict[str, Any]:
    users = []
    seen_user_ids = set()

    for profile_path in sorted(DATA_DIR.glob("*/profile.json")):
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        settings = {**default_profile_settings(), **(profile.get("settings") or {})}
        contacts = [item.strip() for item in settings.get("WHITELIST_SENDERS", "").split(",") if item.strip()]
        users.append(
            {
                "user_id": profile.get("user_id", profile_path.parent.name),
                "source": "profile",
                "email": profile.get("email", ""),
                "whitelist_contacts": contacts,
            }
        )
        seen_user_ids.add(profile.get("user_id", profile_path.parent.name))

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
    contacts = get_contacts_for_user(resolved_user_id)
    profile = load_profile(resolved_user_id)
    source = "profile" if profile else "env"
    return {"user_id": resolved_user_id, "contacts": contacts, "source": source}


@app.post("/whitelist")
def update_whitelist(payload: WhitelistUpdateRequest, request: Request) -> Dict[str, Any]:
    resolved_user_id = resolve_user_id(request, payload.user_id)
    cleaned_contacts = [contact.strip() for contact in payload.contacts if contact.strip()]
    set_contacts_for_user(resolved_user_id, cleaned_contacts)
    return {"user_id": resolved_user_id, "contacts": cleaned_contacts, "success": True}


def get_user_summaries_dir(user_id: str) -> Path:
    return OUTPUT_DIR / user_id / "summaries"


def get_user_json_summaries_dir(user_id: str) -> Path:
    return DATA_DIR / user_id / "summaries"


def get_user_json_emails_dir(user_id: str) -> Path:
    return DATA_DIR / user_id / "emails"


def get_user_processed_state_path(user_id: str) -> Path:
    return OUTPUT_DIR / user_id / "processed_state.json"


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


def load_summary_file(summary_path: Path) -> Dict[str, Any]:
    content = summary_path.read_text(encoding="utf-8")
    stat = summary_path.stat()

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
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    stat = summary_path.stat()
    payload.setdefault("summary_id", summary_path.stem)
    payload.setdefault("user_id", summary_path.parent.parent.name)
    payload.setdefault("filename", summary_path.name)
    payload.setdefault("preview", payload.get("executive_summary") or payload.get("bottom_line") or "")
    payload.setdefault("updated_at", payload.get("created_at") or stat.st_mtime)
    return payload


def load_processed_uids_for_user(user_id: str) -> List[int]:
    path = get_user_processed_state_path(user_id)
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [int(uid) for uid in payload.get("processed_uids", [])]


def save_processed_uids_for_user(user_id: str, uids: List[int]) -> None:
    path = get_user_processed_state_path(user_id)
    payload = {
        "processed_uids": sorted(set(int(uid) for uid in uids)),
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
    payload = json.loads(email_path.read_text(encoding="utf-8"))
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
def get_attachment(user_id: str = Query(...), path: str = Query(...)) -> FileResponse:
    requested_path = (BASE_DIR / path).resolve()
    try:
        requested_path.relative_to(BASE_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid attachment path.") from exc

    if not requested_path.exists() or not requested_path.is_file():
        raise HTTPException(status_code=404, detail=f"Attachment not found for user '{user_id}'.")

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
    removed_uids: List[int] = []
    for email_id in summary_payload.get("source_email_file_ids", []) or []:
        if any(email_id in (other.get("source_email_file_ids", []) or []) for other in other_summaries):
            continue

        email_path = get_user_json_emails_dir(user_id) / f"{email_id}.json"
        if not email_path.exists():
            continue
        email_payload = load_email_json(email_path)
        if email_payload.get("uid") is not None:
            removed_uids.append(int(email_payload["uid"]))
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


def build_combined_summary_context(summaries: List[Dict[str, Any]], max_total_chars: int = 50000) -> str:
    blocks: List[str] = []
    total_chars = 0
    for summary in summaries:
        parts = [
            f"Summary ID: {summary.get('summary_id', '')}",
            f"Title: {summary.get('title', '')}",
            f"Updated At: {summary.get('updated_at', '')}",
        ]
        for label, key, limit in [
            ("Executive Summary", "executive_summary", 1400),
            ("Main Topics", "main_topics", 900),
            ("New Developments", "new_developments", 900),
            ("Action Items", "action_items", 900),
            ("Deadlines", "deadlines", 700),
            ("Attachment Summary", "attachment_summary", 900),
            ("Bottom Line", "bottom_line", 700),
        ]:
            if summary.get(key):
                parts.append(f"{label}:\n{_compact_for_chat(summary[key], limit)}")
        block = _to_ascii_safe("\n".join(parts))
        if total_chars + len(block) > max_total_chars and blocks:
            break
        blocks.append(block)
        total_chars += len(block) + 2
    return "\n\n".join(blocks)


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
    summary_ids = [summary_id.strip() for summary_id in payload.summary_ids if summary_id.strip()]
    if not summary_ids:
        raise HTTPException(status_code=400, detail="Select at least one summary first.")

    summaries: List[Dict[str, Any]] = []
    for summary_id in summary_ids:
        try:
            summaries.append(get_summary(summary_id, request, resolved_user_id))
        except HTTPException:
            continue

    if not summaries:
        raise HTTPException(status_code=404, detail="None of the selected summaries could be loaded.")

    settings = get_settings_for_user(resolved_user_id)
    api_key = settings.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    model = settings.get("OPENAI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o"
    if not api_key:
        raise HTTPException(status_code=500, detail=f"No OPENAI_API_KEY configured for user '{resolved_user_id}'.")

    client = OpenAI(api_key=api_key)
    context = build_combined_summary_context(summaries)
    instructions = (
        "You are writing a combined report across multiple saved email summaries. "
        "Use only the provided summaries. Address the user as 'you'. "
        "Do not invent facts. Prefer practical synthesis over repetition. "
        "Return Markdown with these sections exactly when supported by the context: "
        "## Executive Summary, ## Main Themes, ## Key Action Items, ## Deadlines / Dates, ## Notable Attachments, ## Bottom Line. "
        "Use bullet points where helpful."
    )
    input_text = (
        "SELECTED SUMMARY CONTEXT\n"
        f"{context}\n\n"
        "TASK\n"
        "Create one combined summary that gives an overall report of everything covered by these selected summaries.\n"
    )

    try:
        response = client.responses.create(
            model=model,
            instructions=instructions,
            input=input_text,
            temperature=0.1,
            max_output_tokens=1400,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Combined summary request failed: {exc}") from exc

    return {
        "user_id": resolved_user_id,
        "summary_ids": [summary.get("summary_id", "") for summary in summaries],
        "count": len(summaries),
        "combined_markdown": response.output_text,
        "title": f"Combined Summary ({len(summaries)} Selected)",
    }


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
    json_summaries_dir = get_user_json_summaries_dir(user_id)
    summaries_dir = get_user_summaries_dir(user_id)
    if json_summaries_dir.exists():
        summary_files = sorted(json_summaries_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        summaries = [
            load_summary_json(path)
            for path in summary_files
            if not path.stem.startswith("overall_master_")
        ]
        for summary in summaries:
            summary.pop("summary_markdown", None)
            summary.pop("contact_summaries", None)
        return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "json"}

    if not summaries_dir.exists():
        return {"user_id": user_id, "summaries": [], "message": f"No summaries folder found for user '{user_id}'."}

    summary_files = sorted(summaries_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    summaries = [load_summary_file(path) for path in summary_files]

    for summary in summaries:
        summary.pop("content_markdown", None)

    return {"user_id": user_id, "count": len(summaries), "summaries": summaries, "source": "markdown"}


@app.get("/summaries/{summary_id}")
def get_summary(summary_id: str, request: Request, user_id: Optional[str] = Query(None, description="User folder name, for example 'Ben'")) -> Dict[str, Any]:
    user_id = resolve_user_id(request, user_id)
    json_summary_path = get_user_json_summaries_dir(user_id) / f"{summary_id}.json"
    if json_summary_path.exists():
        return load_summary_json(json_summary_path)

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
