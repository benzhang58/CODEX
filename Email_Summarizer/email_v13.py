"""
Email Summarizer
================
Pipeline:
  1. Fetch recent emails from whitelisted senders (primary IMAP folder)
  2. For each email that is part of a thread, reconstruct the FULL thread —
     every message from every participant, searched across ALL IMAP folders
  3. Extract attachments from EVERY message in the thread (all senders)
  4. Send the complete thread + all attachment previews to the LLM
  5. Write per-contact and master summaries to disk
"""

import os
import json
import logging
import re
import sqlite3
import base64
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set, Tuple, Any
import imaplib
import email
import email.utils
from email.message import Message
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError
import pandas as pd
from pypdf import PdfReader
from docx import Document
import html2text
from openai import OpenAI
from dotenv import load_dotenv, dotenv_values
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from security_utils import decrypt_json_payload, encrypt_json_payload

# Don't load .env at import time — we load the right one at runtime
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
APP_BASE_DIR = Path(__file__).resolve().parent
APP_STORAGE_DIR = Path(os.getenv("EMAIL_SUMMARIZER_STORAGE_DIR", str(APP_BASE_DIR / "data"))).resolve()
OUTPUT_ROOT_DIR = Path(os.getenv("EMAIL_SUMMARIZER_OUTPUT_DIR", str(APP_BASE_DIR / "email_summaries_output"))).resolve()


def available_env_options(cwd: Path = Path(".")) -> List[Path]:
    env_files = sorted(cwd.glob(".env.*"))
    base_env = cwd / ".env"

    options: List[Path] = []
    if base_env.exists():
        options.append(base_env)
    options.extend(env_files)
    return options


def parse_summary_style_preferences(raw_value: str) -> List[str]:
    raw = str(raw_value or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in raw.split("\n") if item.strip()]


def parse_contact_profiles(raw_value: str) -> Dict[str, Dict[str, str]]:
    raw = str(raw_value or "").strip()
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
        if not email_text or not isinstance(value, dict):
            continue
        normalized[email_text] = {
            "first_name": str(value.get("first_name", "") or "").strip(),
            "last_name": str(value.get("last_name", "") or "").strip(),
        }
    return normalized


def get_app_config_value(key: str, cwd: Path = Path(".")) -> str:
    value = os.getenv(key)
    if value:
        return value

    for candidate in (cwd / ".env.google_oauth", cwd / ".env", APP_BASE_DIR / ".env.google_oauth", APP_BASE_DIR / ".env"):
        if candidate.exists():
            parsed = dotenv_values(candidate)
            maybe = parsed.get(key)
            if maybe:
                return str(maybe)
    return ""


def load_client_env_by_name(client_name: str, cwd: Path = Path(".")) -> Path:
    normalized = client_name.strip().lower()
    for option in available_env_options(cwd):
        label = option.name.replace(".env.", "").replace(".env", "default").lower()
        if label == normalized:
            load_dotenv(option, override=True)
            logger.info(f"Loaded config: {option.name}")
            return option
    raise FileNotFoundError(f"No .env file found for client '{client_name}'.")


def load_profile_config_by_user_id(user_id: str, cwd: Path = Path(".")) -> Path:
    base_env_path = cwd / ".env"
    if base_env_path.exists():
        load_dotenv(base_env_path, override=True)

    app_db_path = APP_STORAGE_DIR / "app" / "app.db"
    payload = None
    source_label = ""
    config_reference_path: Optional[Path] = None

    if app_db_path.exists():
        connection = sqlite3.connect(app_db_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT email, settings_json, microsoft_oauth_json FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        finally:
            connection.close()

        if row:
            payload = {
                "email": row["email"],
                "settings": decrypt_json_payload(row["settings_json"] or "{}", APP_STORAGE_DIR),
                "microsoft_oauth": decrypt_json_payload(row["microsoft_oauth_json"] or "{}", APP_STORAGE_DIR),
            }
            source_label = f"database profile: {app_db_path}"
            config_reference_path = app_db_path

    if payload is None:
        profile_path = APP_STORAGE_DIR / "users" / user_id / "profile.json"
        if not profile_path.exists():
            raise FileNotFoundError(f"No profile.json found for user '{user_id}'.")
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
        source_label = f"profile: {profile_path}"
        config_reference_path = profile_path

    settings = payload.get("settings") or {}
    email_value = str(payload.get("email", "")).strip().lower()
    provider_defaults = {
        "IMAP_SERVER": "imap.263.net",
        "IMAP_PORT": "993",
        "SMTP_HOST": "smtp.263.net",
        "SMTP_PORT": "465",
        "IMAP_FOLDER": "INBOX",
    }
    microsoft_oauth = payload.get("microsoft_oauth") or {}
    if str(microsoft_oauth.get("provider", "")).strip().lower() == "microsoft":
        provider_defaults = {
            "IMAP_SERVER": "outlook.office365.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp-mail.outlook.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif email_value.endswith("@gmail.com"):
        provider_defaults = {
            "IMAP_SERVER": "imap.gmail.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }
    elif email_value.endswith(("@outlook.com", "@hotmail.com", "@live.com", "@msn.com")):
        provider_defaults = {
            "IMAP_SERVER": "outlook.office365.com",
            "IMAP_PORT": "993",
            "SMTP_HOST": "smtp-mail.outlook.com",
            "SMTP_PORT": "587",
            "IMAP_FOLDER": "INBOX",
        }

    if provider_defaults:
        settings = {
            **provider_defaults,
            **settings,
            "IMAP_SERVER": settings.get("IMAP_SERVER") or provider_defaults["IMAP_SERVER"],
            "IMAP_PORT": settings.get("IMAP_PORT") or provider_defaults["IMAP_PORT"],
            "SMTP_HOST": settings.get("SMTP_HOST") or provider_defaults["SMTP_HOST"],
            "SMTP_PORT": settings.get("SMTP_PORT") or provider_defaults["SMTP_PORT"],
            "IMAP_FOLDER": settings.get("IMAP_FOLDER") or provider_defaults["IMAP_FOLDER"],
        }

    if email_value:
        settings["IMAP_USER"] = str(settings.get("IMAP_USER") or email_value)
        settings["SMTP_USER"] = str(settings.get("SMTP_USER") or email_value)
        settings["SUMMARY_RECIPIENT"] = str(settings.get("SUMMARY_RECIPIENT") or email_value)

    imap_password = str(settings.get("IMAP_PASSWORD") or "").strip()
    smtp_password = str(settings.get("SMTP_PASSWORD") or "").strip()
    if not imap_password and smtp_password:
        settings["IMAP_PASSWORD"] = smtp_password
    if not smtp_password and imap_password:
        settings["SMTP_PASSWORD"] = imap_password

    for key, value in settings.items():
        if value is None or str(value).strip() == "":
            continue
        os.environ[str(key)] = str(value)

    if payload.get("email"):
        os.environ.setdefault("PROFILE_EMAIL", str(payload["email"]))

    logger.info(f"Loaded config from {source_label}")
    return config_reference_path or base_env_path or cwd


def select_client_env() -> Path:
    """
    Prompt the user to select a client config at runtime.
    Looks for .env files named .env.<clientname> in the current directory,
    e.g. .env.gmail, .env.263, .env.client_acme
    Falls back to .env if only one config exists.
    """
    cwd = Path(".")
    selected_profile = os.getenv("PROFILE_USER_ID")
    if selected_profile:
        return load_profile_config_by_user_id(selected_profile, cwd)

    selected_name = os.getenv("CLIENT_NAME")
    if selected_name:
        return load_client_env_by_name(selected_name, cwd)

    options = available_env_options(cwd)

    if not options:
        raise FileNotFoundError("No .env files found. Create a .env or .env.<clientname> file.")

    # If only a plain .env exists, use it silently
    if len(options) == 1:
        load_dotenv(options[0], override=True)
        logger.info(f"Loaded config: {options[0].name}")
        return options[0]

    print("\n╔══════════════════════════════════════╗")
    print("║       Email Summarizer — Login        ║")
    print("╚══════════════════════════════════════╝")
    print("\nAvailable accounts:\n")
    for i, f in enumerate(options, 1):
        label = f.name.replace(".env.", "").replace(".env", "default")
        print(f"  [{i}] {label}  ({f.name})")
    print()

    while True:
        try:
            choice = input(f"Select account [1-{len(options)}]: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                selected = options[idx]
                load_dotenv(selected, override=True)
                label = selected.name.replace(".env.", "").replace(".env", "default")
                print(f"\n✅ Logged in as: {label}\n")
                logger.info(f"Loaded config: {selected.name}")
                return selected
            else:
                print(f"Please enter a number between 1 and {len(options)}")
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(0)


# ──────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────

@dataclass
class AttachmentInfo:
    filename: str
    saved_path: str
    preview: str
    from_sender: str   # who sent the email this attachment came from
    email_date: str    # ISO date of that email

@dataclass
class ThreadMessage:
    """One message inside a reconstructed thread (any participant)."""
    message_id: str
    sender: str
    to: str
    cc: str
    subject: str
    date: str
    body: str
    attachments: List[AttachmentInfo] = field(default_factory=list)

@dataclass
class EmailRecord:
    """The whitelisted trigger email + its full reconstructed thread."""
    uid: int
    message_id: str
    sender: str
    display_name: str  # human name from From: header e.g. "Wang Li"
    subject: str
    date: str
    # Full thread sorted oldest→newest, INCLUDING the trigger message itself
    thread: List[ThreadMessage] = field(default_factory=list)
    raw_path: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────

class EmailSummarizer:

    MAX_ATTACHMENT_PREVIEW_CHARS = 180
    MAX_SUBJECT_FALLBACK_CANDIDATES = 25

    def __init__(self, output_base: Path, user_id: str):
        self.output_base     = Path(output_base)
        self.attachments_dir = self.output_base / "attachments"
        self.summaries_dir   = self.output_base / "summaries"
        self.json_dir        = self.output_base / "json"
        self.user_id         = user_id

        self.data_user_dir   = APP_STORAGE_DIR / "users" / self.user_id
        self.data_emails_dir = self.data_user_dir / "emails"
        self.data_summaries_dir = self.data_user_dir / "summaries"
        self.data_metadata_path = self.data_user_dir / "metadata.json"

        for d in [
            self.attachments_dir,
            self.summaries_dir,
            self.json_dir,
            self.data_user_dir,
            self.data_emails_dir,
            self.data_summaries_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

        self.state_file    = self.output_base / "processed_state.json"
        self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        configured_model   = str(os.getenv("OPENAI_MODEL", "gpt-5.1") or "").strip()
        self.model         = "gpt-5.1" if not configured_model or configured_model == "gpt-4o" else configured_model

        self.whitelist: List[str] = [
            e.strip().lower()
            for e in os.getenv("WHITELIST_SENDERS", "").split(",")
            if e.strip()
        ]
        self.whitelist_set: Set[str] = set(self.whitelist)
        self.contact_profiles = parse_contact_profiles(os.getenv("CONTACT_PROFILES", ""))
        if not self.whitelist:
            logger.warning("No WHITELIST_SENDERS defined!")

        self._primary_folder = os.getenv("IMAP_FOLDER", "INBOX")
        self.imap_timeout_seconds = int(os.getenv("EMAIL_SUMMARIZER_IMAP_TIMEOUT_SECONDS", "30") or "30")
        self._all_folders: List[str] = []  # populated after connect
        self.profile_email = os.getenv("PROFILE_EMAIL", "").strip().lower()
        self.google_oauth = self._load_google_oauth()
        self.microsoft_oauth = self._load_microsoft_oauth()
        self.use_gmail_api = self._should_use_gmail_api()
        self.use_microsoft_imap_oauth = self._should_use_microsoft_imap_oauth()
        self.include_attachment_previews_in_llm = os.getenv(
            "EMAIL_SUMMARIZER_INCLUDE_ATTACHMENT_PREVIEWS_IN_LLM",
            "false",
        ).lower() == "true"
        self.attachment_retention_days = int(os.getenv("EMAIL_SUMMARIZER_ATTACHMENT_RETENTION_DAYS", "30") or "30")
        self.source_email_retention_days = int(os.getenv("EMAIL_SUMMARIZER_SOURCE_EMAIL_RETENTION_DAYS", "0") or "0")
        self._apply_retention_policy()

    def _message_sender(self, msg: Message) -> str:
        return email.utils.parseaddr(msg.get("From", ""))[1].strip().lower()

    def _is_tracked_sender(self, sender: str) -> bool:
        return str(sender or "").strip().lower() in self.whitelist_set

    @staticmethod
    def _contact_profile_display_name(profile: Dict[str, str]) -> str:
        return " ".join(
            part for part in [str(profile.get("first_name", "")).strip(), str(profile.get("last_name", "")).strip()]
            if part
        ).strip()

    @staticmethod
    def _slugify(value: str) -> str:
        value = re.sub(r'[^A-Za-z0-9._-]+', '_', value.strip())
        value = value.strip('._')
        return value or "item"

    def _message_file_id(self, message_id: str, uid: int) -> str:
        if message_id:
            cleaned = message_id.strip().strip("<>")
            return self._slugify(cleaned)
        return f"uid_{uid}"

    def _load_google_oauth(self) -> Dict[str, Any]:
        app_db_path = APP_STORAGE_DIR / "app" / "app.db"
        if not app_db_path.exists():
            return {}
        connection = sqlite3.connect(app_db_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT google_oauth_json FROM users WHERE user_id = ?",
                (self.user_id,),
            ).fetchone()
        finally:
            connection.close()
        if not row or not row["google_oauth_json"]:
            return {}
        try:
            payload = decrypt_json_payload(row["google_oauth_json"], APP_STORAGE_DIR)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _load_microsoft_oauth(self) -> Dict[str, Any]:
        app_db_path = APP_STORAGE_DIR / "app" / "app.db"
        if not app_db_path.exists():
            return {}
        connection = sqlite3.connect(app_db_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT microsoft_oauth_json FROM users WHERE user_id = ?",
                (self.user_id,),
            ).fetchone()
        finally:
            connection.close()
        if not row or not row["microsoft_oauth_json"]:
            return {}
        try:
            payload = decrypt_json_payload(row["microsoft_oauth_json"], APP_STORAGE_DIR)
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _save_oauth_payload(self, column_name: str, payload: Dict[str, Any]) -> None:
        if column_name not in {"google_oauth_json", "microsoft_oauth_json"}:
            return
        app_db_path = APP_STORAGE_DIR / "app" / "app.db"
        if not app_db_path.exists():
            return
        encrypted_payload = encrypt_json_payload(payload or {}, APP_STORAGE_DIR)
        connection = sqlite3.connect(app_db_path)
        try:
            connection.execute(
                f"UPDATE users SET {column_name} = ?, updated_at = ? WHERE user_id = ?",
                (encrypted_payload, datetime.now().isoformat(), self.user_id),
            )
            connection.commit()
        finally:
            connection.close()

    def _should_use_gmail_api(self) -> bool:
        if not self.profile_email.endswith("@gmail.com"):
            return False
        return bool(self.google_oauth.get("refresh_token") or self.google_oauth.get("access_token"))

    def _should_use_microsoft_imap_oauth(self) -> bool:
        if self.use_gmail_api:
            return False
        provider = str(self.microsoft_oauth.get("provider", "")).strip().lower()
        if provider != "microsoft":
            return False
        return bool(self.microsoft_oauth.get("refresh_token") or self.microsoft_oauth.get("access_token"))

    def _prune_path_tree(self, root: Path, retention_days: int):
        if retention_days <= 0 or not root.exists():
            return
        cutoff = datetime.now() - timedelta(days=retention_days)
        for path in sorted(root.rglob("*"), reverse=True):
            try:
                if not path.exists():
                    continue
                modified = datetime.fromtimestamp(path.stat().st_mtime)
                if modified >= cutoff:
                    continue
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    try:
                        path.rmdir()
                    except OSError:
                        pass
            except Exception as exc:
                logger.warning(f"Retention cleanup skipped for {path}: {exc}")

    def _apply_retention_policy(self):
        self._prune_path_tree(self.attachments_dir, self.attachment_retention_days)
        if self.source_email_retention_days > 0:
            self._prune_path_tree(self.data_emails_dir, self.source_email_retention_days)

    @staticmethod
    def _uid_token(uid: Any) -> str:
        return str(uid).strip()

    @staticmethod
    def _gmail_numeric_uid(gmail_message_id: str) -> int:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", str(gmail_message_id))
        if cleaned:
            return int(cleaned[:15], 16)
        return abs(hash(gmail_message_id)) % (10**15)

    def _gmail_refresh_access_token(self) -> str:
        refresh_token = str(self.google_oauth.get("refresh_token", "")).strip()
        if not refresh_token:
            raise ValueError("Google mailbox access expired. Sign in with Google again to reconnect your mailbox.")

        client_id = get_app_config_value("GOOGLE_CLIENT_ID", APP_BASE_DIR)
        client_secret = get_app_config_value("GOOGLE_CLIENT_SECRET", APP_BASE_DIR)
        if not client_id or not client_secret:
            raise ValueError("Google OAuth client settings are missing.")

        body = urlencode(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode("utf-8")
        request = UrlRequest(
            "https://oauth2.googleapis.com/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Google token refresh failed: {payload}") from exc

        new_access_token = str(payload.get("access_token", "")).strip()
        if not new_access_token:
            raise ValueError("Google token refresh did not return an access token.")
        self.google_oauth["access_token"] = new_access_token
        self.google_oauth["updated_at"] = datetime.now().isoformat()
        self._save_oauth_payload("google_oauth_json", self.google_oauth)
        return new_access_token

    def _microsoft_refresh_access_token(self) -> str:
        refresh_token = str(self.microsoft_oauth.get("refresh_token", "")).strip()
        if not refresh_token:
            raise ValueError("Microsoft mailbox access expired. Sign in with Microsoft again to reconnect your mailbox.")

        client_id = get_app_config_value("MICROSOFT_CLIENT_ID", APP_BASE_DIR)
        client_secret = get_app_config_value("MICROSOFT_CLIENT_SECRET", APP_BASE_DIR)
        tenant_id = get_app_config_value("MICROSOFT_TENANT_ID", APP_BASE_DIR) or "common"
        if not client_id or not client_secret:
            raise ValueError("Microsoft OAuth client settings are missing.")

        body = urlencode(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            }
        ).encode("utf-8")
        request = UrlRequest(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Microsoft token refresh failed: {payload}") from exc

        new_access_token = str(payload.get("access_token", "")).strip()
        if not new_access_token:
            raise ValueError("Microsoft token refresh did not return an access token.")
        self.microsoft_oauth["access_token"] = new_access_token
        maybe_refresh_token = str(payload.get("refresh_token", "")).strip()
        if maybe_refresh_token:
            self.microsoft_oauth["refresh_token"] = maybe_refresh_token
        self.microsoft_oauth["updated_at"] = datetime.now().isoformat()
        self._save_oauth_payload("microsoft_oauth_json", self.microsoft_oauth)
        return new_access_token

    @staticmethod
    def _build_xoauth2_string(user: str, access_token: str) -> bytes:
        return f"user={user}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")

    def _gmail_api_json(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        access_token = self._gmail_refresh_access_token()
        query = f"?{urlencode(params)}" if params else ""
        request = UrlRequest(
            f"https://gmail.googleapis.com/gmail/v1/users/me/{path}{query}",
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Gmail API request failed for {path}: {payload}") from exc

    def _gmail_api_raw_message(self, gmail_message_id: str) -> Message:
        payload = self._gmail_api_json(f"messages/{gmail_message_id}", {"format": "raw"})
        raw_value = payload.get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_value.encode("utf-8"))
        parsed = email.message_from_bytes(raw_bytes)
        parsed.uid = self._gmail_numeric_uid(gmail_message_id)
        parsed.gmail_message_id = gmail_message_id
        parsed.gmail_thread_id = payload.get("threadId", "")
        return parsed

    def _summary_file_id(self, sender: str, run_date: str) -> str:
        return self._slugify(f"{sender}_{run_date}")

    @staticmethod
    def _extract_section(markdown: str, section_name: str) -> str:
        lines = markdown.splitlines()
        target = f"## {section_name}".lower()
        collecting = False
        collected: List[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.lower() == target:
                collecting = True
                continue
            if collecting and stripped.startswith("## "):
                break
            if collecting:
                collected.append(line)

        return "\n".join(collected).strip()

    def _summary_payload(
        self,
        summary_id: str,
        sender: str,
        label: str,
        run_date: str,
        run_date_display: str,
        summary_markdown: str,
        records: List[EmailRecord],
    ) -> Dict[str, object]:
        source_message_ids = [record.message_id for record in records if record.message_id]
        related_thread_message_ids = sorted({
            tm.message_id for record in records for tm in record.thread if tm.message_id
        })
        attachment_names = sorted({
            att.filename for record in records for tm in record.thread for att in tm.attachments
        })

        return {
            "summary_id": summary_id,
            "user_id": self.user_id,
            "sender": sender,
            "contact_label": label,
            "title": f"Email Summary — {label}",
            "run_date": run_date,
            "run_date_display": run_date_display,
            "summary_markdown": summary_markdown,
            "executive_summary": self._extract_section(summary_markdown, "Executive Summary"),
            "thread_context": self._extract_section(summary_markdown, "Thread Context"),
            "main_topics": self._extract_section(summary_markdown, "Main Topics"),
            "new_developments": self._extract_section(summary_markdown, "New Developments"),
            "action_items": self._extract_section(summary_markdown, "Action Items / Asks"),
            "deadlines": self._extract_section(summary_markdown, "Deadlines / Dates / Meetings"),
            "risks": self._extract_section(summary_markdown, "Risks / Things to Watch"),
            "attachment_summary": self._extract_section(summary_markdown, "Attachment Summary"),
            "bottom_line": self._extract_section(summary_markdown, "Bottom Line"),
            "source_uids": [str(record.uid).strip() for record in records if str(record.uid).strip()],
            "source_message_ids": source_message_ids,
            "related_thread_message_ids": related_thread_message_ids,
            "source_email_file_ids": [self._message_file_id(record.message_id, record.uid) for record in records],
            "attachment_filenames": attachment_names,
            "record_count": len(records),
            "created_at": datetime.now().isoformat(),
        }

    def _save_email_record_json(self, record: EmailRecord, run_date: str):
        file_id = self._message_file_id(record.message_id, record.uid)
        payload = {
            "email_id": file_id,
            "user_id": self.user_id,
            "run_date": run_date,
            "uid": record.uid,
            "message_id": record.message_id,
            "sender": record.sender,
            "display_name": record.display_name,
            "subject": record.subject,
            "date": record.date,
            "raw_path": record.raw_path,
            "thread_message_ids": [tm.message_id for tm in record.thread if tm.message_id],
            "thread": [asdict(tm) for tm in record.thread],
            "created_at": datetime.now().isoformat(),
        }
        out_path = self.data_emails_dir / f"{file_id}.json"
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Wrote product email JSON: {out_path.name}")

    def _save_summary_json(self, summary_payload: Dict[str, object]):
        out_path = self.data_summaries_dir / f"{summary_payload['summary_id']}.json"
        out_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Wrote product summary JSON: {out_path.name}")

    def _save_metadata(self, run_date: str, run_date_display: str, days_back: int, records: List[EmailRecord], summary_ids: List[str]):
        metadata = {
            "user_id": self.user_id,
            "last_run": datetime.now().isoformat(),
            "last_run_id": run_date,
            "last_run_display": run_date_display,
            "days_back": days_back,
            "total_new_records_last_run": len(records),
            "last_summary_ids": summary_ids,
        }
        self.data_metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Wrote metadata: {self.data_metadata_path.name}")

    # ──────────────────────────────────────────────
    # State persistence
    # ──────────────────────────────────────────────

    def load_processed_uids(self) -> Set[str]:
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    loaded = {self._uid_token(uid) for uid in json.load(f).get("processed_uids", [])}
                existing_saved_uids: Set[str] = set()
                for email_path in self.data_emails_dir.glob("*.json"):
                    try:
                        payload = json.loads(email_path.read_text(encoding="utf-8"))
                        uid = payload.get("uid")
                        if uid is not None:
                            existing_saved_uids.add(self._uid_token(uid))
                    except Exception:
                        continue

                # Clean up stale processed UIDs that no longer have a saved email
                # record behind them. This prevents old runs from blocking a
                # summary from reappearing after its saved data was deleted.
                if existing_saved_uids:
                    reconciled = loaded & existing_saved_uids
                else:
                    reconciled = set()

                if reconciled != loaded:
                    logger.info(f"Reconciled processed UIDs: {len(loaded)} -> {len(reconciled)}")
                    self.save_processed_uids(reconciled)
                return reconciled
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return set()

    def save_processed_uids(self, uids: Set[str]):
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump({"processed_uids": sorted(str(uid) for uid in uids), "last_run": datetime.now().isoformat()}, f, indent=2)
            logger.info(f"Saved state: {len(uids)} processed UIDs")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    # ──────────────────────────────────────────────
    # IMAP helpers
    # ──────────────────────────────────────────────

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        if self.use_gmail_api:
            raise ValueError("IMAP should not be used for Gmail accounts with Google OAuth tokens.")
        server   = os.getenv("IMAP_SERVER")
        port     = int(os.getenv("IMAP_PORT", 993))
        user     = os.getenv("IMAP_USER")
        password = os.getenv("IMAP_PASSWORD")

        if self.use_microsoft_imap_oauth:
            server = "outlook.office365.com"
            port = 993
            user = user or str(self.microsoft_oauth.get("email", "")).strip() or self.profile_email
            if not all([server, user]):
                raise ValueError("Missing Outlook IMAP settings for Microsoft OAuth mailbox access.")
        elif not all([server, user, password]):
            raise ValueError("Missing IMAP credentials.")

        logger.info(f"Connecting to {server}:{port}")
        mail = imaplib.IMAP4_SSL(server, port, timeout=self.imap_timeout_seconds)
        try:
            mail.sock.settimeout(self.imap_timeout_seconds)
        except Exception:
            pass
        if self.use_microsoft_imap_oauth:
            access_token = self._microsoft_refresh_access_token()
            auth_string = self._build_xoauth2_string(user, access_token)
            mail.authenticate("XOAUTH2", lambda _: auth_string)
        else:
            mail.login(user, password)
        mail.select(self._primary_folder)

        self._all_folders = self._list_all_folders(mail)
        logger.info(f"Discovered {len(self._all_folders)} folder(s).")
        return mail

    # Folders to skip during thread reconstruction — never contain real thread messages
    # Includes English, decoded Chinese (263.com), and raw encoded equivalents
    _SKIP_FOLDERS = {
        "[Gmail]/Spam", "[Gmail]/Trash", "[Gmail]/Drafts",
        "Spam", "Junk", "Junk E-mail", "Trash", "Deleted Messages", "Drafts",
        "垃圾邮件", "已删除", "草稿箱", "草稿",        # 263.com decoded Chinese
        "&V4NXPpCuTvY-", "&XfJSIJZk-", "&g0l6P3ux-",  # 263.com raw encoded (spam, deleted, drafts)
    }
    # Search these first — they mirror all/most mail so we find messages faster
    _PRIORITY_FOLDERS = [
        "[Gmail]/All Mail", "All Mail",
        "INBOX",
        "Sent Messages", "[Gmail]/Sent Mail",
        "已发送", "&XfJT0ZAB-",  # 263.com sent folder (decoded + raw encoded)
    ]

    def _is_263_mailbox(self) -> bool:
        server = os.getenv("IMAP_SERVER", "").strip().lower()
        email_value = self.profile_email.strip().lower()
        return "263" in server or email_value.endswith("@263.com") or email_value.endswith("@263.net")

    def _thread_search_folders(self) -> List[str]:
        if not self._all_folders:
            return []

        if self.use_gmail_api:
            return self._all_folders

        if self._is_263_mailbox():
            preferred = {"INBOX", "Sent Messages", "已发送", "&XfJT0ZAB-"}
            narrowed = [folder for folder in self._all_folders if folder in preferred]
            if narrowed:
                return narrowed

        return self._all_folders

    def _list_all_folders(self, mail: imaplib.IMAP4_SSL) -> List[str]:
        import re
        _, folders = mail.list()
        if not folders:
            return []
        names = []
        for f in folders:
            decoded = f.decode() if isinstance(f, bytes) else f
            if not decoded:
                continue
            if r'\Noselect' in decoded:
                continue
            quoted = re.findall(r'"([^"]+)"', decoded)
            name = quoted[-1] if quoted else decoded.strip().split()[-1]
            name = name.strip()
            if name and name != '/':
                names.append(name)
        # Decode UTF-7 encoded names (e.g. 263.com Chinese folders like &XfJT0ZAB-)
        # We keep the raw names for IMAP SELECT but log decoded names for readability
        decoded_map = {n: self._decode_folder_name(n) for n in names}
        decoded_names = list(decoded_map.values())

        # Build priority/skip sets using decoded names
        skip_decoded  = self._SKIP_FOLDERS
        priority_decoded = self._PRIORITY_FOLDERS

        priority = [n for n in names if decoded_map[n] in priority_decoded or n in priority_decoded]
        rest     = [n for n in names if n not in priority
                    and decoded_map[n] not in skip_decoded
                    and n not in skip_decoded]
        ordered  = priority + rest
        logger.info(f"Thread search prepared across {len(ordered)} folder(s).")
        return ordered

    @staticmethod
    def _parse_uids(data: list) -> List[int]:
        """
        Safely parse a UID SEARCH response into a list of ints.
        Some IMAP servers (e.g. 263.com) include the literal word 'UID'
        or other tokens in the response — we skip anything non-numeric.
        """
        uids = []
        if not data or not data[0]:
            return uids
        for token in data[0].split():
            try:
                uids.append(int(token))
            except (ValueError, TypeError):
                continue  # skip non-numeric tokens like b'UID'
        return uids

    @staticmethod
    def _decode_folder_name(name: str) -> str:
        """
        Decode IMAP modified UTF-7 folder names (e.g. '&XfJT0ZAB-' → '已发送').
        IMAP uses a modified UTF-7 where base64 chunks use , instead of /
        and are wrapped in &...-.
        """
        import re, base64
        def replacer(m):
            b64 = m.group(1)
            if not b64:
                return '&'  # &- is escaped &
            try:
                padded = b64.replace(',', '/')
                padded += '=' * (4 - len(padded) % 4) if len(padded) % 4 else ''
                return base64.b64decode(padded).decode('utf-16-be')
            except Exception:
                return m.group(0)
        try:
            return re.sub(r'&([^-]*)-', replacer, name)
        except Exception:
            return name

    @staticmethod
    def _decode_subject(subject: str) -> str:
        """Decode RFC2047-encoded email subjects (e.g. =?utf-8?b?...? or =?utf-8?q?...?)."""
        try:
            from email.header import decode_header
            parts = decode_header(subject)
            decoded = []
            for part, charset in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(charset or 'utf-8', errors='replace'))
                else:
                    decoded.append(part)
            return ''.join(decoded)
        except Exception:
            return subject

    def _deduplicate_triggers_by_thread(self, msgs: List[Message]) -> List[Message]:
        """
        Group trigger emails by thread (using References/In-Reply-To root ID,
        falling back to normalized subject). Within each thread, keep only the
        most recent message as the trigger — the thread reconstruction will
        fetch all prior messages anyway, so processing multiple triggers from
        the same thread is pure redundant work.
        """
        import re

        def get_thread_key(msg: Message) -> str:
            # Use the root Message-ID from References chain as the thread key
            refs = msg.get("References", "").strip().split()
            if refs:
                return refs[0].strip()  # oldest reference = thread root
            in_reply = msg.get("In-Reply-To", "").strip()
            if in_reply:
                return in_reply
            # Standalone — use normalized subject as key
            subj = self._decode_subject(msg.get("Subject", "")).strip()
            subj = re.sub(r'^(Re:|RE:|Fwd:|FWD:)\s*', '', subj, flags=re.IGNORECASE).strip()
            return f"subj::{subj}"

        def get_date(msg: Message) -> datetime:
            try:
                return email.utils.parsedate_to_datetime(msg.get("Date", "")).replace(tzinfo=None)
            except Exception:
                return datetime.min

        # Group by thread key, keeping track of all msgs per thread
        threads: Dict[str, List[Message]] = defaultdict(list)
        for msg in msgs:
            key = get_thread_key(msg)
            threads[key].append(msg)

        # From each thread group, keep only the most recent trigger
        deduped = []
        for key, group in threads.items():
            most_recent = max(group, key=get_date)
            if len(group) > 1:
                logger.info(f"Thread dedup: keeping most recent of {len(group)} triggers.")
            deduped.append(most_recent)

        logger.info(f"Thread dedup: {len(msgs)} trigger(s) → {len(deduped)} unique thread(s)")
        return deduped

    def _select(self, mail: imaplib.IMAP4_SSL, folder: str, readonly: bool = True) -> bool:
        try:
            status, _ = mail.select(f'"{folder}"', readonly=readonly)
            return status == 'OK'
        except Exception:
            return False

    def _restore_primary(self, mail: imaplib.IMAP4_SSL):
        try:
            mail.select(self._primary_folder)
        except Exception:
            pass

    def _fetch_raw(self, mail: imaplib.IMAP4_SSL, uid: int) -> Optional[Message]:
        try:
            _, msg_data = mail.uid('FETCH', str(uid), '(RFC822)')
            if msg_data and msg_data[0]:
                parsed = email.message_from_bytes(msg_data[0][1])
                parsed.uid = uid
                return parsed
        except Exception as e:
            logger.warning(f"Could not fetch UID {uid}: {e}")
        return None

    def _search_across_all_folders(self, mail: imaplib.IMAP4_SSL, imap_query: str,
                                       stop_at_first: bool = False) -> List[Tuple[str, int]]:
        """
        Run an IMAP SEARCH across every folder (in priority order).
        stop_at_first=True  → stop as soon as any folder returns results.
                               Use for Message-ID lookups: a message exists in exactly one place.
        stop_at_first=False → search all folders and collect all results.
                               Use for subject-line fallback where multiple folders may match.
        Restores primary folder when done.
        """
        results: List[Tuple[str, int]] = []
        for folder in self._thread_search_folders():
            if not self._select(mail, folder, readonly=True):
                continue
            try:
                _, data = mail.uid('SEARCH', None, imap_query)
                parsed_uids = self._parse_uids(data)
                if parsed_uids:
                    for uid in parsed_uids:
                        results.append((folder, uid))
                    if stop_at_first:
                        break  # found it — no need to check remaining folders
            except Exception:
                continue
        self._restore_primary(mail)
        return results

    # ──────────────────────────────────────────────
    # Fetch whitelisted trigger emails
    # ──────────────────────────────────────────────

    def fetch_trigger_emails(self, mail: Optional[imaplib.IMAP4_SSL], days_back: int, processed_uids: Set[str]) -> Tuple[List[Message], Dict[str, int]]:
        """
        Fetch recent emails from whitelisted senders.
        Search by FROM only — no combined SINCE+FROM — because some servers (e.g. 263.com)
        silently return empty results for combined criteria. Date filtering done in Python.
        """
        if self.use_gmail_api:
            return self.fetch_trigger_emails_gmail_api(days_back, processed_uids)

        since_dt = datetime.now() - timedelta(days=days_back)
        logger.info(f"Searching for whitelisted emails since {since_dt.strftime('%d-%b-%Y')} (date filtered in Python)")

        # Strategy: run SINCE and FROM as separate queries, intersect in Python.
        # This avoids combined SINCE+FROM queries that 263.com silently rejects,
        # while still being efficient — we only fetch headers for emails that
        # pass BOTH filters, not all historical emails from these senders.
        since_date = since_dt.strftime("%d-%b-%Y")

        # Step 1: get all UIDs since the date cutoff
        try:
            _, data = mail.uid('SEARCH', None, f'SINCE {since_date}')
            recent_uids: Set[int] = set(self._parse_uids(data))
            logger.info(f"SINCE {since_date} → {len(recent_uids)} recent email(s) in INBOX")
        except Exception as e:
            logger.warning(f"SINCE search failed: {e}, falling back to ALL")
            _, data = mail.uid('SEARCH', None, 'ALL')
            recent_uids = set(self._parse_uids(data))

        # Step 2: get UIDs from each whitelisted sender, intersect with recent
        if not self.whitelist:
            logger.info("No tracked senders configured; skipping trigger search.")
            return [], {
                "candidate_trigger_count": 0,
                "already_processed_count": 0,
                "untracked_sender_count": 0,
                "new_trigger_count": 0,
            }

        all_uids: Set[int] = set()
        for sender in self.whitelist:
            try:
                _, data = mail.uid('SEARCH', None, f'FROM "{sender}"')
                sender_uids = set(self._parse_uids(data))
                matched = sender_uids & recent_uids  # intersection
                logger.info(f"Matched {len(matched)} recent email(s) for one tracked sender.")
                all_uids.update(matched)
            except Exception as e:
                logger.warning(f"  FROM search failed for '{sender}': {e}")

        uid_list = sorted(all_uids)
        logger.info(f"Combined search: {len(uid_list)} candidate email(s) to process.")

        msgs = []
        skipped_processed = 0
        skipped_untracked_sender = 0
        for uid in uid_list:
            if self._uid_token(uid) in processed_uids:
                logger.info(f"  Skipping UID {uid} (already processed)")
                skipped_processed += 1
                continue
            msg = self._fetch_raw(mail, uid)
            if msg:
                sender = self._message_sender(msg)
                if not self._is_tracked_sender(sender):
                    skipped_untracked_sender += 1
                    logger.info(f"  Skipping UID {uid} because actual From is not tracked: {sender or '(empty)'}")
                    continue
                msgs.append(msg)

        logger.info(f"Found {len(msgs)} new trigger email(s)")
        return msgs, {
            "candidate_trigger_count": len(uid_list),
            "already_processed_count": skipped_processed,
            "untracked_sender_count": skipped_untracked_sender,
            "new_trigger_count": len(msgs),
        }

    def fetch_trigger_emails_gmail_api(self, days_back: int, processed_uids: Set[str]) -> Tuple[List[Message], Dict[str, int]]:
        if not self.whitelist:
            logger.info("No tracked senders configured; skipping Gmail trigger search.")
            return [], {
                "candidate_trigger_count": 0,
                "already_processed_count": 0,
                "untracked_sender_count": 0,
                "new_trigger_count": 0,
            }

        logger.info("Running Gmail API search for tracked senders.")

        candidate_ids: List[str] = []
        seen_candidate_ids: Set[str] = set()
        for tracked_sender in self.whitelist:
            query = " ".join([f"newer_than:{max(1, days_back)}d", "-in:trash", "-in:spam", f"from:{tracked_sender}"])
            next_page_token: Optional[str] = None
            while True:
                params = {"q": query, "maxResults": "100"}
                if next_page_token:
                    params["pageToken"] = next_page_token
                payload = self._gmail_api_json("messages", params)
                for msg in payload.get("messages", []):
                    gmail_id = msg.get("id", "")
                    if gmail_id and gmail_id not in seen_candidate_ids:
                        seen_candidate_ids.add(gmail_id)
                        candidate_ids.append(gmail_id)
                next_page_token = payload.get("nextPageToken")
                if not next_page_token:
                    break

        logger.info(f"Gmail API returned {len(candidate_ids)} candidate message(s)")
        msgs: List[Message] = []
        skipped_processed = 0
        skipped_untracked_sender = 0
        for gmail_message_id in candidate_ids:
            numeric_uid = self._gmail_numeric_uid(gmail_message_id)
            if self._uid_token(numeric_uid) in processed_uids:
                skipped_processed += 1
                continue
            try:
                msg = self._gmail_api_raw_message(gmail_message_id)
                sender = self._message_sender(msg)
                if not self._is_tracked_sender(sender):
                    skipped_untracked_sender += 1
                    logger.info(f"Skipping Gmail candidate {gmail_message_id} because actual From is not tracked: {sender or '(empty)'}")
                    continue
                msgs.append(msg)
            except Exception as exc:
                logger.warning(f"Failed to fetch Gmail message {gmail_message_id}: {exc}")

        logger.info(f"Found {len(msgs)} new Gmail trigger email(s)")
        return msgs, {
            "candidate_trigger_count": len(candidate_ids),
            "already_processed_count": skipped_processed,
            "untracked_sender_count": skipped_untracked_sender,
            "new_trigger_count": len(msgs),
        }

    # ──────────────────────────────────────────────
    # Thread reconstruction
    # ──────────────────────────────────────────────

    def _get_referenced_ids(self, msg: Message) -> Set[str]:
        """Pull all Message-IDs from In-Reply-To and References headers."""
        ids: Set[str] = set()
        for header in ["In-Reply-To", "References"]:
            for part in msg.get(header, "").split():
                part = part.strip()
                if part:
                    ids.add(part)
        return ids

    def _fetch_full_thread(self, mail: Optional[imaplib.IMAP4_SSL], trigger: Message) -> List[ThreadMessage]:
        """
        Reconstruct the complete thread for a trigger email.
        Searches ALL IMAP folders for every related message.
        Uses both Message-ID header traversal and subject-line fallback.
        Returns all thread messages sorted oldest→newest (trigger included).
        """
        if self.use_gmail_api and getattr(trigger, "gmail_thread_id", ""):
            return self._fetch_full_thread_gmail_api(trigger)

        own_mid       = trigger.get("Message-ID", "").strip()
        referenced    = self._get_referenced_ids(trigger)
        is_threaded   = bool(referenced)

        # key: message_id → raw Message object
        collected: Dict[str, Message] = {}
        fetched_uids: Set[int] = set()  # prevent re-fetching same UID via different paths
        if own_mid:
            collected[own_mid] = trigger
            if getattr(trigger, 'uid', 0):
                fetched_uids.add(getattr(trigger, 'uid', 0))

        if not is_threaded:
            logger.info("Standalone email detected.")
            return [self._to_thread_message(trigger, mail)]

        logger.info("Fetching full thread for trigger email.")

        # ── BFS over the Message-ID reference graph ──
        queue         = list(referenced)
        visited: Set[str] = {own_mid}

        while queue:
            mid = queue.pop()
            if mid in visited:
                continue
            visited.add(mid)

            # stop_at_first=True: Message-IDs are unique, stop at first folder hit
            hits = self._search_across_all_folders(mail, f'HEADER Message-ID "{mid}"', stop_at_first=True)
            for folder, uid in hits:
                if uid in fetched_uids:
                    break  # already processed this message via a different path
                if not self._select(mail, folder, readonly=True):
                    continue
                msg = self._fetch_raw(mail, uid)
                self._restore_primary(mail)
                if not msg:
                    continue
                fetched_uids.add(uid)
                msg_id = msg.get("Message-ID", "").strip() or mid
                if msg_id not in collected:
                    collected[msg_id] = msg
                    for new_ref in self._get_referenced_ids(msg):
                        if new_ref not in visited:
                            queue.append(new_ref)
                break

        # ── Subject-line fallback (catches broken/missing headers) ──
        raw_subject   = trigger.get("Subject", "")
        clean_subject = raw_subject
        for pfx in ["Re:", "RE:", "Fwd:", "FWD:", "re:", "fwd:"]:
            clean_subject = clean_subject.replace(pfx, "").strip()

        if clean_subject:
            # [Gmail]/All Mail mirrors everything — one search is enough.
            # Fall back to full folder list only if All Mail isn't available.
            all_mail = [f for f in self._all_folders if f in ("[Gmail]/All Mail", "All Mail")]
            subject_folders = all_mail if all_mail else self._thread_search_folders()

            subject_hits: List[Tuple[str, int]] = []
            for folder in subject_folders:
                if not self._select(mail, folder, readonly=True):
                    continue
                try:
                    _, data = mail.uid('SEARCH', None, f'SUBJECT "{clean_subject}"')
                    for uid in self._parse_uids(data):
                        subject_hits.append((folder, uid))
                        if len(subject_hits) >= self.MAX_SUBJECT_FALLBACK_CANDIDATES:
                            break
                except Exception:
                    continue
                if len(subject_hits) >= self.MAX_SUBJECT_FALLBACK_CANDIDATES:
                    break
            self._restore_primary(mail)

            for folder, uid in subject_hits:
                if uid in fetched_uids:
                    continue  # already have this message
                if not self._select(mail, folder, readonly=True):
                    continue
                msg = self._fetch_raw(mail, uid)
                self._restore_primary(mail)
                if not msg:
                    continue
                msg_id = msg.get("Message-ID", "").strip()
                if msg_id and msg_id not in collected:
                    fetched_uids.add(uid)
                    collected[msg_id] = msg
                    logger.info("Subject fallback added one related thread message.")

        logger.info(f"Thread total: {len(collected)} message(s) found across all folders")

        # ── Convert and sort oldest → newest ──
        thread_msgs = [self._to_thread_message(m, mail) for m in collected.values()]
        thread_msgs.sort(key=lambda m: m.date)
        return thread_msgs

    def _fetch_full_thread_gmail_api(self, trigger: Message) -> List[ThreadMessage]:
        thread_id = getattr(trigger, "gmail_thread_id", "")
        if not thread_id:
            return [self._to_thread_message(trigger, None)]

        payload = self._gmail_api_json(f"threads/{thread_id}")
        messages: List[Message] = []
        for item in payload.get("messages", []):
            gmail_message_id = item.get("id", "")
            if not gmail_message_id:
                continue
            try:
                messages.append(self._gmail_api_raw_message(gmail_message_id))
            except Exception as exc:
                logger.warning(f"Failed to fetch Gmail thread message {gmail_message_id}: {exc}")
        if not messages:
            return [self._to_thread_message(trigger, None)]
        thread_msgs = [self._to_thread_message(msg, None) for msg in messages]
        thread_msgs.sort(key=lambda m: m.date)
        return thread_msgs

    def _to_thread_message(self, msg: Message, mail: imaplib.IMAP4_SSL) -> ThreadMessage:
        """Convert a raw Message into a ThreadMessage, extracting body + all attachments."""
        sender   = email.utils.parseaddr(msg.get("From", ""))[1].lower()
        date_str = msg.get("Date", "")
        try:
            date_iso = email.utils.parsedate_to_datetime(date_str).isoformat()
        except Exception:
            date_iso = datetime.now().isoformat()

        body        = self._extract_body(msg)
        uid         = getattr(msg, 'uid', 0)
        attachments = self._extract_attachments(msg, uid, sender, date_iso)

        return ThreadMessage(
            message_id=msg.get("Message-ID", "").strip(),
            sender=sender,
            to=msg.get("To", ""),
            cc=msg.get("Cc", ""),
            subject=self._decode_subject(msg.get("Subject", "(no subject)")),
            date=date_iso,
            body=body,
            attachments=attachments,
        )

    # ──────────────────────────────────────────────
    # Body extraction
    # ──────────────────────────────────────────────

    def _extract_body(self, msg: Message) -> str:
        """
        Extract readable body text.
        Each message in the thread is fetched individually so we do NOT strip
        entire reply chains — we only remove inline-quoted lines (>) to avoid
        redundancy since prior messages are already fetched separately.
        """
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if "attachment" in str(part.get("Content-Disposition", "")).lower():
                    continue
                if ct == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='replace')
                        break
                elif ct == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        h = html2text.HTML2Text()
                        h.ignore_links = True
                        h.ignore_images = True
                        body = h.handle(payload.decode('utf-8', errors='replace'))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == "text/html":
                    h = html2text.HTML2Text()
                    h.ignore_links = True
                    h.ignore_images = True
                    body = h.handle(payload.decode('utf-8', errors='replace'))
                else:
                    body = payload.decode('utf-8', errors='replace')

        # Strip inline quoted lines (>) and common reply-header noise — those
        # messages are fetched separately and otherwise bloat prompt size.
        lines   = body.splitlines()
        cleaned = []
        skip_patterns = [
            r"^On .+wrote:$",
            r"^From:\s",
            r"^Sent:\s",
            r"^To:\s",
            r"^Subject:\s",
            r"^-{2,}\s*Original Message\s*-{2,}$",
        ]
        for line in lines:
            stripped = line.strip()
            if not stripped.startswith(">") and not any(re.match(pattern, stripped, flags=re.IGNORECASE) for pattern in skip_patterns):
                cleaned.append(line)
        body    = "\n".join(cleaned).strip()

        return body

    # ──────────────────────────────────────────────
    # Attachment extraction
    # ──────────────────────────────────────────────

    def _extract_attachments(self, msg: Message, uid: int, sender: str, date_iso: str) -> List[AttachmentInfo]:
        """Extract, save, and preview all attachments from a single message."""
        attachments = []
        subdir = self.attachments_dir / f"email_{uid}"
        subdir.mkdir(exist_ok=True)

        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            disposition = str(part.get("Content-Disposition", "")).lower()
            filename    = part.get_filename()
            if not ("attachment" in disposition or filename):
                continue
            if not filename:
                continue

            filename  = self._decode_subject(filename)  # decode RFC2047 encoded filenames
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
            save_path = subdir / f"uid_{uid}_{safe_name}"

            # Skip inline images — these are embedded in email bodies, not real attachments.
            # Indicators: no file extension, UUID-style name, or Content-Disposition=inline
            import re as _re
            has_extension = bool(_re.search(r'\.[a-zA-Z0-9]{1,5}$', filename))
            is_uuid_name  = bool(_re.match(r'^[0-9A-Fa-f\-]{20,}(\.[a-zA-Z]+)?$', filename))
            is_inline     = "inline" in str(part.get("Content-Disposition", "")).lower() and part.get_filename()
            if not has_extension or is_uuid_name or is_inline:
                logger.debug(f"Skipping inline/embedded image: {filename}")
                continue

            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                if len(payload) >= 10 * 1024 * 1024:
                    logger.warning("Skipped large attachment (>10MB).")
                    attachments.append(AttachmentInfo(
                        filename=filename, saved_path="",
                        preview="Attachment too large for preview.",
                        from_sender=sender, email_date=date_iso,
                    ))
                    continue
                with open(save_path, "wb") as f:
                    f.write(payload)
                preview = self._preview_attachment(save_path, filename)
                attachments.append(AttachmentInfo(
                    filename=filename, saved_path=str(save_path), preview=preview,
                    from_sender=sender, email_date=date_iso,
                ))
                logger.info("Saved attachment.")
            except Exception as e:
                logger.error(f"Error processing attachment: {e}")
                attachments.append(AttachmentInfo(
                    filename=filename, saved_path="", preview=f"Error: {e}",
                    from_sender=sender, email_date=date_iso,
                ))

        return attachments

    def _preview_attachment(self, filepath: Path, filename: str) -> str:
        ext = filepath.suffix.lower()
        try:
            if ext in ['.csv', '.tsv']:
                sep = '\t' if ext == '.tsv' else ','
                df  = pd.read_csv(filepath, sep=sep, nrows=10, on_bad_lines='skip')
                out = f"CSV/TSV — {len(df.columns)} columns: {list(df.columns[:10])}\n"
                out += df.head(3).to_string(index=False)
                return out[:1500]
            elif ext in ['.xlsx', '.xls', '.xlsm']:
                try:
                    df = pd.read_excel(filepath, nrows=10, engine='openpyxl')
                except Exception:
                    df = pd.read_excel(filepath, nrows=10)
                out = f"Excel — {len(df.columns)} columns: {list(df.columns[:10])}\n"
                out += df.head(3).to_string(index=False)
                return out[:1500]
            elif ext == '.pdf':
                reader = PdfReader(filepath)
                text   = "".join((p.extract_text() or "") for p in reader.pages[:3])
                return f"PDF preview:\n{text[:2000].strip()}" if text.strip() else "PDF: no extractable text."
            elif ext in ['.docx', '.doc']:
                doc  = Document(filepath)
                text = "\n".join(p.text.strip() for p in doc.paragraphs if p.text.strip())
                return f"DOCX preview:\n{text[:2000]}" if text else "DOCX: no text."
            elif ext in ['.txt', '.md', '.log']:
                return filepath.read_text(encoding='utf-8', errors='replace')[:2000]
            else:
                return "Binary attachment — no text preview available."
        except Exception as e:
            return f"Preview failed: {e}"

    @staticmethod
    def _compact_text(text: str) -> str:
        lines = [line.rstrip() for line in text.splitlines()]
        compacted: List[str] = []
        blank_count = 0
        for line in lines:
            if line.strip():
                blank_count = 0
                compacted.append(line)
            else:
                blank_count += 1
                if blank_count <= 1:
                    compacted.append("")
        return "\n".join(compacted).strip()

    def _body_for_llm(self, body: str, is_trigger: bool) -> str:
        return self._compact_text(body)

    def _attachment_preview_for_llm(self, preview: str) -> str:
        compact = self._compact_text(preview)
        max_chars = self.MAX_ATTACHMENT_PREVIEW_CHARS
        if len(compact) > max_chars:
            return compact[:max_chars] + "\n... [truncated]"
        return compact

    # ──────────────────────────────────────────────
    # Parse one trigger email → EmailRecord
    # ──────────────────────────────────────────────

    def parse_email(self, msg: Message, mail: imaplib.IMAP4_SSL) -> Optional[EmailRecord]:
        try:
            uid        = getattr(msg, 'uid', 0)
            message_id = msg.get("Message-ID", "")
            from_parts   = email.utils.parseaddr(msg.get("From", ""))
            display_name = self._decode_subject(from_parts[0].strip()) or from_parts[1].split("@")[0]
            sender       = self._message_sender(msg)
            if not self._is_tracked_sender(sender):
                logger.info(f"Skipping parsed email because actual From is not tracked: {sender or '(empty)'}")
                return None
            subject      = self._decode_subject(msg.get("Subject", "(no subject)"))
            date_str   = msg.get("Date", "")
            try:
                date_iso = email.utils.parsedate_to_datetime(date_str).isoformat()
            except Exception:
                date_iso = datetime.now().isoformat()

            # Reconstruct full thread (includes the trigger itself)
            thread = self._fetch_full_thread(mail, msg)

            raw_path = None

            return EmailRecord(
                uid=uid,
                message_id=message_id,
                sender=sender,
                display_name=display_name,
                subject=subject,
                date=date_iso,
                thread=thread,
                raw_path=str(raw_path) if raw_path else None,
            )
        except Exception as e:
            logger.error(f"Error parsing email UID {getattr(msg, 'uid', '?')}: {e}")
            return None

    # ──────────────────────────────────────────────
    # LLM prompt formatting
    # ──────────────────────────────────────────────

    def _format_record_for_llm(self, record: EmailRecord) -> str:
        """Render a full EmailRecord (thread + all attachments) into a structured prompt block."""
        lines = []

        # ── Thread messages ──
        if len(record.thread) <= 1:
            lines.append("=== STANDALONE EMAIL (no prior thread) ===")
        else:
            lines.append(f"=== FULL EMAIL THREAD — {len(record.thread)} messages (oldest → newest) ===")

        for i, tm in enumerate(record.thread, 1):
            is_trigger = (tm.message_id == record.message_id)
            label      = "★ NEW EMAIL (the one that triggered this summary)" if is_trigger else f"Message {i} of {len(record.thread)}"
            parts      = f"From: {tm.sender}"
            if tm.to:
                parts += f"  |  To: {tm.to}"
            if tm.cc:
                parts += f"  |  CC: {tm.cc}"

            lines.append(f"\n{'─'*60}")
            lines.append(label)
            lines.append(f"Date:    {tm.date}")
            lines.append(parts)
            lines.append(f"Subject: {tm.subject}")
            body_preview = self._body_for_llm(tm.body, is_trigger=is_trigger)
            lines.append(f"\n{body_preview or '[No body text]'}")

            if tm.attachments:
                lines.append(f"\n  → {len(tm.attachments)} attachment(s) in this message:")
                for att in tm.attachments:
                    lines.append(f"     • {att.filename}")

        # ── Consolidated attachment section (deduplicated by filename, most recent wins) ──
        # Thread is sorted oldest→newest, so iterating and overwriting gives us
        # the most recent version of each file when the same name appears multiple times.
        latest_by_filename: Dict[str, AttachmentInfo] = {}
        for tm in record.thread:
            for att in tm.attachments:
                latest_by_filename[att.filename] = att  # later iteration overwrites older
        unique_attachments = list(latest_by_filename.values())

        lines.append(f"\n{'='*60}")
        if unique_attachments:
            lines.append(f"=== ALL ATTACHMENTS IN THREAD ({len(unique_attachments)} unique files) ===")
            for att in unique_attachments:
                lines.append(f"\n── File: {att.filename} ──")
                if self.include_attachment_previews_in_llm:
                    preview_text = self._attachment_preview_for_llm(att.preview)
                    if preview_text:
                        lines.append(f"   Preview:\n{preview_text}")
                    else:
                        lines.append("   Preview omitted to keep the summary request within model limits.")
                else:
                    lines.append("   Preview withheld for privacy. Use filename only unless local review is required.")
        else:
            lines.append("=== NO ATTACHMENTS IN THIS THREAD ===")

        return "\n".join(lines)

    def _build_summary_prompt(
        self,
        records: List[EmailRecord],
        preamble: str,
        preference_block: str,
        section_guide: str,
    ) -> Tuple[str, str]:
        data_block = "\n\n".join(self._format_record_for_llm(r) for r in records)
        return preamble + preference_block + data_block + "\n\n" + section_guide, data_block

    # ──────────────────────────────────────────────
    # Summary generation
    # ──────────────────────────────────────────────

    def generate_summary(self, records: List[EmailRecord], contact_name: Optional[str] = None, is_overall: bool = False) -> str:
        if not records:
            return "No emails to summarize."

        if is_overall:
            instructions = (
                "You are an executive business analyst producing a master weekly briefing "
                "across multiple key contacts. Be precise, factual, and note uncertainties."
            )
            preamble = (
                "OVERALL WEEKLY SUMMARY\n\n"
                "Below are all recent emails from key contacts, each with their full thread "
                "context and all attachments from all participants. Synthesize into one report.\n\n"
            )
        else:
            instructions = (
                f"You are a precise business analyst summarizing all recent email activity "
                f"from contact: {contact_name}. Be factual and note uncertainties."
            )
            preamble = (
                f"CONTACT SUMMARY — {contact_name}\n\n"
                f"Below are all recent emails from this contact, with full thread context "
                f"and all attachments from all participants in each thread.\n\n"
            )

        summary_preferences = parse_summary_style_preferences(os.getenv("SUMMARY_STYLE_PREFERENCES", ""))
        preference_block = ""
        if summary_preferences:
            preference_block = (
                "USER SUMMARY STYLE PREFERENCES\n"
                "Apply these preferences when writing the summary unless they conflict with the actual email content or required sections:\n"
                + "\n".join(f"- {item}" for item in summary_preferences)
                + "\n\n"
            )

        # Build explicit attachment checklist so the LLM cannot skip any file
        all_attachment_names = []
        for record in records:
            seen: Set[str] = set()
            for tm in record.thread:
                for att in tm.attachments:
                    if att.filename not in seen:
                        seen.add(att.filename)
                        all_attachment_names.append(att.filename)

        if all_attachment_names:
            if self.include_attachment_previews_in_llm:
                attachment_instruction = (
                    "## Attachment Summary\n"
                    "You MUST write exactly one bullet point for EACH of the following files — "
                    "do not skip, group, or merge any of them:\n"
                    + "\n".join(f"  - {name}" for name in all_attachment_names)
                    + "\n\nFor each bullet: state the filename, what it contains, "
                    "and why it matters. Do not include who sent it or any dates.\n\n"
                )
            else:
                attachment_instruction = (
                    "## Attachment Summary\n"
                    "You MUST write exactly one bullet point for EACH of the following files — "
                    "do not skip, group, or merge any of them:\n"
                    + "\n".join(f"  - {name}" for name in all_attachment_names)
                    + "\n\nPrivacy mode is enabled: do not infer attachment contents from the filename alone. "
                    "Only describe attachment content if it is explicitly stated in the email text. Otherwise say the file was attached but its contents were not inspected.\n\n"
                )
        else:
            attachment_instruction = ""

        section_guide = (
            "Output ONLY clean Markdown. CRITICAL RULES:\n"
            "1. OMIT any section entirely if it has nothing to say — do NOT write 'None mentioned'.\n"
            "2. Use exactly these section headers (## prefix), only including ones with real content:\n\n"
            "## Thread Context\n"
            "Conversation history leading up to the new email. Omit if standalone.\n\n"
            "## Executive Summary\n"
            "What is this person communicating in their latest message(s)?\n\n"
            "## Main Topics\n"
            "Key subjects discussed across the thread(s).\n\n"
            "## New Developments\n"
            "What is new or changed compared to prior messages.\n\n"
            "## Action Items / Asks\n"
            "Anything requested of you or others. Omit if none.\n\n"
            "## Deadlines / Dates / Meetings\n"
            "All time-sensitive items. Omit if none.\n\n"
            "## Risks / Things to Watch\n"
            "Issues or concerns raised. Omit if none.\n\n"
            + attachment_instruction
            + "## Bottom Line\n"
            "2-3 sentences in plain English: what do I need to know and what do I need to do?\n"
        )

        full_input, _ = self._build_summary_prompt(records, preamble, preference_block, section_guide)
        estimated_tokens = max(1, len(full_input) // 4)

        logger.info(f"LLM prompt length: {len(full_input)} chars (~{estimated_tokens} tokens)")

        try:
            response = self.openai_client.responses.create(
                model=self.model,
                instructions=instructions,
                input=full_input,
                temperature=0.0,
                max_output_tokens=5000,
            )
            summary = str(getattr(response, "output_text", "") or "").strip()
            if not summary:
                raise RuntimeError("OpenAI returned empty summary text.")
            logger.info(f"✅ Generated {'overall' if is_overall else 'contact'} summary")
            return summary
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return f"Summary generation failed: {e}"

    # ──────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────

    # ──────────────────────────────────────────────
    # Summary email sending
    # ──────────────────────────────────────────────

    def _markdown_to_html(self, text: str, is_first_contact_section: bool = False) -> str:
        """
        Convert the simple Markdown the LLM produces into clean HTML.
        ## Executive Summary gets bigger treatment; all other ## headers are
        indented sub-headers so the visual hierarchy is clear at a glance.
        """
        import re
        lines   = text.splitlines()
        html    = []
        in_list = False

        for line in lines:
            s = line.strip()

            if in_list and not (s.startswith("- ") or s.startswith("* ")):
                html.append("</ul>")
                in_list = False

            if not s:
                if not in_list:
                    html.append('<div style="height:6px;"></div>')
                continue

            if s.startswith("### "):
                t = self._inline_html(s[4:])
                html.append(f'<h4 style="margin:10px 0 2px 24px; text-decoration:underline; font-size:13px;">{t}</h4>')
            elif s.startswith("## "):
                t = self._inline_html(s[3:])
                if t.strip().lower() == "executive summary":
                    # Bigger, no indent — anchor of each contact section
                    html.append(f'<h3 style="margin:18px 0 6px 0; font-size:16px; text-decoration:underline; color:#1a1a2e;">{t}</h3>')
                else:
                    # Indented sub-header for all other sections
                    html.append(f'<h4 style="margin:14px 0 4px 20px; font-size:13px; text-decoration:underline; color:#333;">{t}</h4>')
            elif s.startswith("# "):
                t = self._inline_html(s[2:])
                html.append(f'<h2 style="margin:22px 0 8px 0; text-decoration:underline;">{t}</h2>')
            elif s.startswith("- ") or s.startswith("* "):
                if not in_list:
                    html.append('<ul style="margin:4px 0 4px 36px; padding:0;">')
                    in_list = True
                t = self._inline_html(s[2:])
                html.append(f"<li>{t}</li>")
            else:
                t = self._inline_html(s)
                html.append(f'<p style="margin:3px 0 3px 20px; font-size:13px;">{t}</p>')

        if in_list:
            html.append("</ul>")

        return "\n".join(html)

    def _inline_html(self, text: str) -> str:
        """Convert **bold** and *italic* markdown to HTML tags."""
        import re
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"\*(.+?)\*",       r"<em>\1</em>",         text)
        return text

    def _build_master_html(self, contact_summaries: Dict[str, str], display_date: str, contact_display: Dict[str, str] = None) -> str:
        """
        Build the full HTML email body — one clearly separated section per contact.
        """
        parts = [
            f'''<html><body style="font-family: Arial, sans-serif; font-size: 14px; color: #1a1a1a; max-width: 800px; margin: auto; padding: 24px;">''',
            f'<h1 style="text-decoration:underline; border-bottom: 2px solid #333; padding-bottom:8px;">',
            f'{display_date}</h1>',
            f'<p style="color:#666; margin-bottom:24px;">Generated automatically. {len(contact_summaries)} contact(s) below.</p>',
        ]

        contact_display = contact_display or {}
        for i, (sender, summary_md) in enumerate(contact_summaries.items()):
            if i > 0:
                parts.append('<hr style="border:none; border-top:2px solid #ccc; margin:32px 0;">')
            label = contact_display.get(sender, sender)
            parts.append(f'<div style="margin-bottom:8px;">')
            parts.append(f'<h2 style="text-decoration:underline; color:#1a1a2e; margin-bottom:4px;">{label}</h2>')
            parts.append('</div>')
            parts.append(self._markdown_to_html(summary_md))

        parts.append('</body></html>')
        return "\n".join(parts)

    def send_summary_email(self, contact_summaries: Dict[str, str], run_date: str, run_date_display: str = "", contact_display: Dict[str, str] = None):
        """Send the master summary as a formatted HTML email via SMTP."""
        smtp_host     = os.getenv("SMTP_HOST")
        smtp_port     = int(os.getenv("SMTP_PORT", 465))
        smtp_user     = os.getenv("SMTP_USER")       # your sending address
        smtp_password = os.getenv("SMTP_PASSWORD")
        # Default recipient to the inbox we're already logged into
        recipient = os.getenv("SUMMARY_RECIPIENT") or os.getenv("IMAP_USER")

        if not all([smtp_host, smtp_user, smtp_password, recipient]):
            logger.error(
                "Missing SMTP config. Set SMTP_HOST, SMTP_PORT, SMTP_USER, "
                "SMTP_PASSWORD in your .env (SUMMARY_RECIPIENT defaults to IMAP_USER)"
            )
            return

        display_date = run_date_display or run_date.replace("_", " ")
        subject      = f"📬 {display_date}"
        html_body    = self._build_master_html(contact_summaries, display_date, contact_display or {})

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = recipient
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            # Port 465 → SSL from the start; port 587 → STARTTLS
            if smtp_port == 587:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                    server.ehlo()
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.sendmail(smtp_user, [recipient], msg.as_bytes())
            else:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
                    server.login(smtp_user, smtp_password)
                    server.sendmail(smtp_user, [recipient], msg.as_bytes())

            logger.info("Summary email sent.")
        except Exception as e:
            logger.error(f"Failed to send summary email: {e}")

    # ──────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────

    def run(self, days_back: int = 7) -> Dict[str, object]:
        run_started_at = time.perf_counter()
        stage_timings: Dict[str, float] = {}

        processed_uids = self.load_processed_uids()
        mail: Optional[imaplib.IMAP4_SSL] = None
        if not self.use_gmail_api:
            connect_started_at = time.perf_counter()
            mail = self.connect_imap()
            stage_timings["imap_connect_seconds"] = round(time.perf_counter() - connect_started_at, 3)

        try:
            trigger_started_at = time.perf_counter()
            trigger_msgs, trigger_stats = self.fetch_trigger_emails(mail, days_back, processed_uids)
            stage_timings["trigger_search_seconds"] = round(time.perf_counter() - trigger_started_at, 3)

            records: List[EmailRecord] = []
            new_uids: Set[str]         = set()
            now = datetime.now()
            run_date     = now.strftime("%Y-%m-%d_%H%M")   # file-safe key
            # e.g. "Summary (Last 7 Days): Tuesday, April 8th, 2026 [3:40 PM PST]"
            day_num    = int(now.strftime("%-d"))
            day_suffix = {1: "st", 2: "nd", 3: "rd"}.get(day_num % 10 if day_num not in (11,12,13) else 0, "th")
            run_date_display = (
                f"Summary (Last {days_back} Day{'s' if days_back != 1 else ''}): "
                f"{now.strftime('%A, %B %-d')}{day_suffix}, "
                f"{now.strftime('%Y')} "
                f"[{now.strftime('%-I:%M %p')} PST]"
            )

            # Deduplicate: if multiple triggers belong to the same thread,
            # keep only the most recent — thread reconstruction fetches all anyway
            trigger_msgs = self._deduplicate_triggers_by_thread(trigger_msgs)
            unique_thread_count = len(trigger_msgs)

            parse_started_at = time.perf_counter()
            for msg in trigger_msgs:
                record = self.parse_email(msg, mail)
                if record:
                    records.append(record)
                    new_uids.add(self._uid_token(record.uid))
                    self._save_email_record_json(record, run_date)
            stage_timings["thread_parse_and_save_seconds"] = round(time.perf_counter() - parse_started_at, 3)

            if not records:
                logger.info("No new emails from whitelisted contacts this run.")
                stage_timings["total_run_seconds"] = round(time.perf_counter() - run_started_at, 3)
                stats = {
                    **trigger_stats,
                    "unique_thread_count": unique_thread_count,
                    "new_email_records_saved": 0,
                    "new_contact_summaries_saved": 0,
                    "new_total_summaries_saved": 0,
                    "stage_timings": stage_timings,
                }
                self._save_metadata(run_date, run_date_display, days_back, records, [])
                return stats

            # Group by whitelisted sender
            by_sender: Dict[str, List[EmailRecord]] = defaultdict(list)
            for rec in records:
                by_sender[rec.sender].append(rec)

            logger.info(f"Summarizing {len(records)} email(s) from {len(by_sender)} contact(s).")

            # Build display name map: email → human name
            display_names: Dict[str, str] = {}
            for rec in records:
                if rec.sender not in display_names and rec.display_name:
                    display_names[rec.sender] = rec.display_name
            for sender, profile in self.contact_profiles.items():
                saved_name = self._contact_profile_display_name(profile)
                if saved_name:
                    display_names[sender] = saved_name

            # Generate one summary per contact
            contact_summaries: Dict[str, str] = {}
            contact_display:   Dict[str, str] = {}
            saved_summary_ids: List[str] = []
            summary_started_at = time.perf_counter()
            for sender, recs in by_sender.items():
                name  = display_names.get(sender, sender)
                label = f"{name} ({sender})"
                contact_display[sender] = label
                summary = self.generate_summary(recs, contact_name=label)
                if summary.startswith("Summary generation failed:"):
                    raise RuntimeError(summary)
                contact_summaries[sender] = summary

                # Also save individual .md file to disk
                safe     = sender.replace("@", "_at_").replace(".", "_")
                out_path = self.summaries_dir / f"{safe}_{run_date}.md"
                out_path.write_text(f"# Email Summary — {label}\n\n{summary}", encoding="utf-8")
                logger.info(f"Wrote: {out_path.name}")

                summary_id = self._summary_file_id(sender, run_date)
                summary_payload = self._summary_payload(
                    summary_id=summary_id,
                    sender=sender,
                    label=label,
                    run_date=run_date,
                    run_date_display=run_date_display,
                    summary_markdown=f"# Email Summary — {label}\n\n{summary}",
                    records=recs,
                )
                self._save_summary_json(summary_payload)
                saved_summary_ids.append(summary_id)
            stage_timings["llm_summary_seconds"] = round(time.perf_counter() - summary_started_at, 3)

            # Save combined master .md to disk
            write_started_at = time.perf_counter()
            master_md = f"# {run_date_display}\n\n"
            master_md += "\n\n---\n\n".join(
                f"## {contact_display.get(sender, sender)}\n\n{summary}"
                for sender, summary in contact_summaries.items()
            )
            master_path = self.summaries_dir / f"OVERALL_MASTER_{run_date}.md"
            master_path.write_text(master_md, encoding="utf-8")
            logger.info(f"Wrote: {master_path.name}")

            master_summary_payload = {
                "summary_id": f"overall_master_{run_date}",
                "user_id": self.user_id,
                "title": run_date_display,
                "run_date": run_date,
                "run_date_display": run_date_display,
                "summary_markdown": master_md,
                "contact_summaries": [
                    {
                        "sender": sender,
                        "contact_label": contact_display.get(sender, sender),
                        "summary_id": self._summary_file_id(sender, run_date),
                        "summary_markdown": summary,
                    }
                    for sender, summary in contact_summaries.items()
                ],
                "source_message_ids": [record.message_id for record in records if record.message_id],
                "created_at": datetime.now().isoformat(),
            }
            self._save_summary_json(master_summary_payload)
            saved_summary_ids.append(master_summary_payload["summary_id"])

            # JSON export
            json_path = self.json_dir / f"emails_{run_date}.json"
            json_path.write_text(
                json.dumps([asdict(r) for r in records], indent=2, default=str),
                encoding="utf-8",
            )
            stage_timings["final_write_seconds"] = round(time.perf_counter() - write_started_at, 3)

            processed_uids.update(new_uids)
            self.save_processed_uids(processed_uids)
            self._save_metadata(run_date, run_date_display, days_back, records, saved_summary_ids)
            logger.info("✅ Pipeline complete.")
            stage_timings["total_run_seconds"] = round(time.perf_counter() - run_started_at, 3)
            return {
                **trigger_stats,
                "unique_thread_count": unique_thread_count,
                "new_email_records_saved": len(records),
                "new_contact_summaries_saved": len(by_sender),
                "new_total_summaries_saved": len(saved_summary_ids),
                "stage_timings": stage_timings,
            }

        finally:
            if mail is not None:
                try:
                    mail.close()
                    mail.logout()
                except Exception:
                    pass


if __name__ == "__main__":
    config_path = select_client_env()
    profile_user_id = os.getenv("PROFILE_USER_ID")
    if profile_user_id:
        client_name = profile_user_id
    else:
        client_name = config_path.name.replace(".env.", "").replace(".env", "default")
    output_dir  = OUTPUT_ROOT_DIR / client_name
    summarizer  = EmailSummarizer(output_dir, user_id=client_name)
    stats = summarizer.run(days_back=int(os.getenv("DAYS_BACK", 7)))
    print(json.dumps({"success": True, "stats": stats}))
