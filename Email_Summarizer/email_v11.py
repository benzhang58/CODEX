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
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set, Tuple
import imaplib
import email
import email.utils
from email.message import Message
import pandas as pd
from pypdf import PdfReader
from docx import Document
import html2text
from openai import OpenAI
from dotenv import load_dotenv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Don't load .env at import time — we load the right one at runtime
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def select_client_env() -> Path:
    """
    Prompt the user to select a client config at runtime.
    Looks for .env files named .env.<clientname> in the current directory,
    e.g. .env.gmail, .env.263, .env.client_acme
    Falls back to .env if only one config exists.
    """
    cwd = Path(".")

    # Find all .env.<name> files
    env_files = sorted(cwd.glob(".env.*"))
    base_env  = cwd / ".env"

    if not env_files and not base_env.exists():
        raise FileNotFoundError("No .env files found. Create a .env or .env.<clientname> file.")

    # If only a plain .env exists, use it silently
    if not env_files and base_env.exists():
        load_dotenv(base_env, override=True)
        logger.info(f"Loaded config: .env")
        return base_env

    # If only one named env exists (and no plain .env), use it silently
    if len(env_files) == 1 and not base_env.exists():
        load_dotenv(env_files[0], override=True)
        logger.info(f"Loaded config: {env_files[0].name}")
        return env_files[0]

    # Build menu
    options: List[Path] = []
    if base_env.exists():
        options.append(base_env)
    options.extend(env_files)

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
    subject: str
    date: str
    # Full thread sorted oldest→newest, INCLUDING the trigger message itself
    thread: List[ThreadMessage] = field(default_factory=list)
    raw_path: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────

class EmailSummarizer:

    def __init__(self, output_base: Path):
        self.output_base     = Path(output_base)
        self.raw_dir         = self.output_base / "raw_emails"
        self.attachments_dir = self.output_base / "attachments"
        self.summaries_dir   = self.output_base / "summaries"
        self.json_dir        = self.output_base / "json"

        for d in [self.raw_dir, self.attachments_dir, self.summaries_dir, self.json_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self.state_file    = self.output_base / "processed_state.json"
        self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model         = os.getenv("OPENAI_MODEL", "gpt-4o")

        self.whitelist: List[str] = [
            e.strip().lower()
            for e in os.getenv("WHITELIST_SENDERS", "").split(",")
            if e.strip()
        ]
        if not self.whitelist:
            logger.warning("No WHITELIST_SENDERS defined!")

        self._primary_folder = os.getenv("IMAP_FOLDER", "INBOX")
        self._all_folders: List[str] = []  # populated after connect

    # ──────────────────────────────────────────────
    # State persistence
    # ──────────────────────────────────────────────

    def load_processed_uids(self) -> Set[int]:
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return set(json.load(f).get("processed_uids", []))
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return set()

    def save_processed_uids(self, uids: Set[int]):
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump({"processed_uids": sorted(uids), "last_run": datetime.now().isoformat()}, f, indent=2)
            logger.info(f"Saved state: {len(uids)} processed UIDs")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    # ──────────────────────────────────────────────
    # IMAP helpers
    # ──────────────────────────────────────────────

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        server   = os.getenv("IMAP_SERVER")
        port     = int(os.getenv("IMAP_PORT", 993))
        user     = os.getenv("IMAP_USER")
        password = os.getenv("IMAP_PASSWORD")

        if not all([server, user, password]):
            raise ValueError("Missing IMAP credentials.")

        logger.info(f"Connecting to {server}:{port}")
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        mail.select(self._primary_folder)

        self._all_folders = self._list_all_folders(mail)
        logger.info(f"Discovered {len(self._all_folders)} folder(s): {self._all_folders}")
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
        logger.info(f"Folders discovered (decoded): {decoded_names}")
        logger.info(f"Thread search order (decoded): {[decoded_map[n] for n in ordered]}")
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
                skipped = [m.get("Subject", "")[:40] for m in group if m is not most_recent]
                logger.info(f"Thread dedup: keeping most recent of {len(group)} triggers, skipping: {skipped}")
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
        for folder in self._all_folders:
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

    def fetch_trigger_emails(self, mail: imaplib.IMAP4_SSL, days_back: int, processed_uids: Set[int]) -> List[Message]:
        """
        Fetch recent emails from whitelisted senders.
        Search by FROM only — no combined SINCE+FROM — because some servers (e.g. 263.com)
        silently return empty results for combined criteria. Date filtering done in Python.
        """
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
        all_uids: Set[int] = set()
        if not self.whitelist:
            all_uids = recent_uids
        else:
            for sender in self.whitelist:
                try:
                    _, data = mail.uid('SEARCH', None, f'FROM "{sender}"')
                    sender_uids = set(self._parse_uids(data))
                    matched = sender_uids & recent_uids  # intersection
                    logger.info(f"  FROM '{sender}' → {len(sender_uids)} total, {len(matched)} recent")
                    all_uids.update(matched)
                except Exception as e:
                    logger.warning(f"  FROM search failed for '{sender}': {e}")

        uid_list = sorted(all_uids)
        logger.info(f"Combined search: {len(uid_list)} candidate(s) to process: {uid_list[:10]}")

        msgs = []
        for uid in uid_list:
            if uid in processed_uids:
                logger.info(f"  Skipping UID {uid} (already processed)")
                continue
            msg = self._fetch_raw(mail, uid)
            if msg:
                sender = email.utils.parseaddr(msg.get("From", ""))[1].lower()
                logger.info(f"  UID {uid}: from={sender} subject={msg.get('Subject','')[:50]}")
                msgs.append(msg)

        logger.info(f"Found {len(msgs)} new trigger email(s)")
        return msgs

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

    def _fetch_full_thread(self, mail: imaplib.IMAP4_SSL, trigger: Message) -> List[ThreadMessage]:
        """
        Reconstruct the complete thread for a trigger email.
        Searches ALL IMAP folders for every related message.
        Uses both Message-ID header traversal and subject-line fallback.
        Returns all thread messages sorted oldest→newest (trigger included).
        """
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
            logger.info(f"Standalone email: {trigger.get('Subject', '')[:60]}")
            return [self._to_thread_message(trigger, mail)]

        logger.info(f"Fetching full thread for: {trigger.get('Subject', '')[:60]}")

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
            subject_folders = all_mail if all_mail else self._all_folders

            subject_hits: List[Tuple[str, int]] = []
            for folder in subject_folders:
                if not self._select(mail, folder, readonly=True):
                    continue
                try:
                    _, data = mail.uid('SEARCH', None, f'SUBJECT "{clean_subject}"')
                    for uid in self._parse_uids(data):
                        subject_hits.append((folder, uid))
                except Exception:
                    continue
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
                    logger.info(f"Subject fallback added message from '{folder}': {msg.get('Subject','')[:50]}")

        logger.info(f"Thread total: {len(collected)} message(s) found across all folders")

        # ── Convert and sort oldest → newest ──
        thread_msgs = [self._to_thread_message(m, mail) for m in collected.values()]
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

        # Strip inline quoted lines (>) — those messages are fetched separately
        lines   = body.splitlines()
        cleaned = [line for line in lines if not line.strip().startswith(">")]
        body    = "\n".join(cleaned).strip()

        if len(body) > 10000:
            body = body[:10000] + "\n... [truncated]"
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
                    logger.warning(f"Skipped large attachment (>10MB): {filename}")
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
                logger.info(f"Saved attachment: {save_path.name}")
            except Exception as e:
                logger.error(f"Error processing attachment {filename}: {e}")
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

    # ──────────────────────────────────────────────
    # Parse one trigger email → EmailRecord
    # ──────────────────────────────────────────────

    def parse_email(self, msg: Message, mail: imaplib.IMAP4_SSL) -> Optional[EmailRecord]:
        try:
            uid        = getattr(msg, 'uid', 0)
            message_id = msg.get("Message-ID", "")
            sender     = email.utils.parseaddr(msg.get("From", ""))[1].lower()
            subject    = self._decode_subject(msg.get("Subject", "(no subject)"))
            date_str   = msg.get("Date", "")
            try:
                date_iso = email.utils.parsedate_to_datetime(date_str).isoformat()
            except Exception:
                date_iso = datetime.now().isoformat()

            # Reconstruct full thread (includes the trigger itself)
            thread = self._fetch_full_thread(mail, msg)

            # Write debug raw file showing the complete thread
            raw_path = self.raw_dir / f"uid_{uid}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(f"TRIGGER: {subject} | From: {sender} | {date_iso}\n")
                f.write(f"THREAD LENGTH: {len(thread)} messages\n\n")
                for i, tm in enumerate(thread, 1):
                    marker = "★ NEW" if tm.message_id == message_id else f"[{i}]"
                    f.write(f"{marker} {tm.date} | From: {tm.sender}\n")
                    f.write(tm.body + "\n")
                    for att in tm.attachments:
                        f.write(f"  [ATTACHMENT] {att.filename}\n")
                    f.write("\n" + "-"*60 + "\n\n")

            return EmailRecord(
                uid=uid,
                message_id=message_id,
                sender=sender,
                subject=subject,
                date=date_iso,
                thread=thread,
                raw_path=str(raw_path),
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
            body_preview = tm.body[:2000] + ("\n... [truncated]" if len(tm.body) > 2000 else "")
            lines.append(f"\n{body_preview}")

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
                lines.append(f"   Sent by: {att.from_sender}")
                lines.append(f"   Preview:\n{att.preview[:600]}")
        else:
            lines.append("=== NO ATTACHMENTS IN THIS THREAD ===")

        return "\n".join(lines)

    # ──────────────────────────────────────────────
    # Summary generation
    # ──────────────────────────────────────────────

    def generate_summary(self, records: List[EmailRecord], contact_name: Optional[str] = None, is_overall: bool = False) -> str:
        if not records:
            return "No emails to summarize."

        data_block = "\n\n".join(self._format_record_for_llm(r) for r in records)

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
            attachment_instruction = (
                "## Attachment Summary\n"
                "You MUST write exactly one bullet point for EACH of the following files — "
                "do not skip, group, or merge any of them:\n"
                + "\n".join(f"  - {name}" for name in all_attachment_names)
                + "\n\nFor each bullet: state the filename, what it contains, "
                "and why it matters. Do not include who sent it or any dates.\n\n"
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

        full_input = preamble + data_block + "\n\n" + section_guide
        logger.info(f"LLM prompt length: {len(full_input)} chars (~{len(full_input)//4} tokens)")
        # Debug: log unique attachments going into the prompt
        for record in records:
            latest: Dict[str, AttachmentInfo] = {}
            for tm in record.thread:
                for att in tm.attachments:
                    latest[att.filename] = att
            logger.info(f"  {len(latest)} unique attachment(s) for UID {record.uid}:")
            for fname, att in latest.items():
                logger.info(f"    {fname} | preview_len={len(att.preview)} | sender={att.from_sender}")

        try:
            response = self.openai_client.responses.create(
                model=self.model,
                instructions=instructions,
                input=full_input,
                temperature=0.0,
                max_output_tokens=8000,
            )
            summary = response.output_text
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

    def _build_master_html(self, contact_summaries: Dict[str, str], display_date: str) -> str:
        """
        Build the full HTML email body — one clearly separated section per contact.
        """
        parts = [
            f'''<html><body style="font-family: Arial, sans-serif; font-size: 14px; color: #1a1a1a; max-width: 800px; margin: auto; padding: 24px;">''',
            f'<h1 style="text-decoration:underline; border-bottom: 2px solid #333; padding-bottom:8px;">',
            f'Weekly Email Summary — {display_date}</h1>',
            f'<p style="color:#666; margin-bottom:24px;">Generated automatically. {len(contact_summaries)} contact(s) below.</p>',
        ]

        for i, (sender, summary_md) in enumerate(contact_summaries.items()):
            if i > 0:
                parts.append('<hr style="border:none; border-top:2px solid #ccc; margin:32px 0;">')
            parts.append(
                f'<div style="margin-bottom:8px;">',
            )
            parts.append(
                f'<h2 style="text-decoration:underline; color:#1a1a2e; margin-bottom:4px;">Contact: {sender}</h2>',
            )
            parts.append('</div>')
            parts.append(self._markdown_to_html(summary_md))

        parts.append('</body></html>')
        return "\n".join(parts)

    def send_summary_email(self, contact_summaries: Dict[str, str], run_date: str, run_date_display: str = ""):
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
        html_body    = self._build_master_html(contact_summaries, display_date)

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

            logger.info(f"✅ Summary email sent to {recipient}")
        except Exception as e:
            logger.error(f"Failed to send summary email: {e}")

    # ──────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────

    def run(self, days_back: int = 7):
        processed_uids = self.load_processed_uids()
        mail           = self.connect_imap()

        try:
            trigger_msgs = self.fetch_trigger_emails(mail, days_back, processed_uids)

            records: List[EmailRecord] = []
            new_uids: Set[int]         = set()
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

            for msg in trigger_msgs:
                record = self.parse_email(msg, mail)
                if record:
                    records.append(record)
                    new_uids.add(record.uid)

            if not records:
                logger.info("No new emails from whitelisted contacts this run.")
                return

            # Group by whitelisted sender
            by_sender: Dict[str, List[EmailRecord]] = defaultdict(list)
            for rec in records:
                by_sender[rec.sender].append(rec)

            logger.info(f"Summarizing {len(records)} email(s) from {len(by_sender)} contact(s).")

            # Generate one summary per contact
            contact_summaries: Dict[str, str] = {}
            for sender, recs in by_sender.items():
                summary = self.generate_summary(recs, contact_name=sender)
                contact_summaries[sender] = summary

                # Also save individual .md file to disk
                safe     = sender.replace("@", "_at_").replace(".", "_")
                out_path = self.summaries_dir / f"{safe}_{run_date}.md"
                out_path.write_text(f"# Email Summary — {sender}\n\n{summary}", encoding="utf-8")
                logger.info(f"Wrote: {out_path.name}")

            # Save combined master .md to disk
            master_md = f"# {run_date_display}\n\n"
            master_md += "\n\n---\n\n".join(
                f"## Contact: {sender}\n\n{summary}"
                for sender, summary in contact_summaries.items()
            )
            master_path = self.summaries_dir / f"OVERALL_MASTER_{run_date}.md"
            master_path.write_text(master_md, encoding="utf-8")
            logger.info(f"Wrote: {master_path.name}")

            # Send the master summary as a formatted HTML email
            self.send_summary_email(contact_summaries, run_date, run_date_display)

            # JSON export
            json_path = self.json_dir / f"emails_{run_date}.json"
            json_path.write_text(
                json.dumps([asdict(r) for r in records], indent=2, default=str),
                encoding="utf-8",
            )

            processed_uids.update(new_uids)
            self.save_processed_uids(processed_uids)
            logger.info("✅ Pipeline complete.")

        finally:
            try:
                mail.close()
                mail.logout()
            except Exception:
                pass


if __name__ == "__main__":
    env_file   = select_client_env()
    # Derive client name from .env filename: .env.gmail → "gmail", .env → "default"
    client_name = env_file.name.replace(".env.", "").replace(".env", "default")
    output_dir  = Path("email_summaries_output") / client_name
    summarizer  = EmailSummarizer(output_dir)
    summarizer.run(days_back=int(os.getenv("DAYS_BACK", 7)))
