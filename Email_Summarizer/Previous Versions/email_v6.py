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

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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
            # Gmail LIST response format: (\HasNoChildren) "/" "INBOX"
            # Extract folder name: last quoted string, or last token if unquoted
            quoted = re.findall(r'"([^"]+)"', decoded)
            if quoted:
                name = quoted[-1]   # last quoted token = folder name (not the "/" delimiter)
            else:
                name = decoded.strip().split()[-1]
            name = name.strip()
            if name and name != '/':
                names.append(name)
        logger.info(f"Folders discovered: {names}")
        return names

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

    def _search_across_all_folders(self, mail: imaplib.IMAP4_SSL, imap_query: str) -> List[Tuple[str, int]]:
        """
        Run an IMAP SEARCH across every folder.
        Returns list of (folder_name, uid). Restores primary folder when done.
        """
        results: List[Tuple[str, int]] = []
        for folder in self._all_folders:
            if not self._select(mail, folder, readonly=True):
                continue
            try:
                _, data = mail.uid('SEARCH', None, imap_query)
                uids = data[0].split() if data and data[0] else []
                for uid_bytes in uids:
                    results.append((folder, int(uid_bytes)))
            except Exception:
                continue
        self._restore_primary(mail)
        return results

    # ──────────────────────────────────────────────
    # Fetch whitelisted trigger emails
    # ──────────────────────────────────────────────

    def fetch_trigger_emails(self, mail: imaplib.IMAP4_SSL, days_back: int, processed_uids: Set[int]) -> List[Message]:
        since_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        logger.info(f"Searching for whitelisted emails since {since_date}")

        if not self.whitelist:
            _, data = mail.uid('SEARCH', None, f'SINCE {since_date}')
        else:
            terms = [f'FROM "{s}"' for s in self.whitelist]
            if len(terms) == 1:
                query = f'(SINCE {since_date} {terms[0]})'
            else:
                or_part = terms[0]
                for t in terms[1:]:
                    or_part = f'(OR {or_part} {t})'
                query = f'(SINCE {since_date} {or_part})'
            _, data = mail.uid('SEARCH', None, query)

        uid_list = data[0].split() if data and data[0] else []
        msgs = []
        for uid_bytes in uid_list:
            uid = int(uid_bytes)
            if uid in processed_uids:
                continue
            msg = self._fetch_raw(mail, uid)
            if msg:
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
        if own_mid:
            collected[own_mid] = trigger

        if not is_threaded:
            logger.info(f"Standalone email: {trigger.get('Subject', '')[:60]}")
            return [self._to_thread_message(trigger, mail)]

        logger.info(f"Fetching full thread for: {trigger.get('Subject', '')[:60]}")

        # ── BFS over the Message-ID reference graph ──
        queue        = list(referenced)
        visited: Set[str] = {own_mid}

        while queue:
            mid = queue.pop()
            if mid in visited:
                continue
            visited.add(mid)

            hits = self._search_across_all_folders(mail, f'HEADER Message-ID "{mid}"')
            for folder, uid in hits:
                if not self._select(mail, folder, readonly=True):
                    continue
                msg = self._fetch_raw(mail, uid)
                self._restore_primary(mail)
                if not msg:
                    continue
                msg_id = msg.get("Message-ID", "").strip() or mid
                if msg_id not in collected:
                    collected[msg_id] = msg
                    # Recurse: queue any new references from this message
                    for new_ref in self._get_referenced_ids(msg):
                        if new_ref not in visited:
                            queue.append(new_ref)
                break  # found in one folder, done for this mid

        # ── Subject-line fallback (catches broken/missing headers) ──
        raw_subject   = trigger.get("Subject", "")
        clean_subject = raw_subject
        for pfx in ["Re:", "RE:", "Fwd:", "FWD:", "re:", "fwd:"]:
            clean_subject = clean_subject.replace(pfx, "").strip()

        if clean_subject:
            hits = self._search_across_all_folders(mail, f'SUBJECT "{clean_subject}"')
            for folder, uid in hits:
                if not self._select(mail, folder, readonly=True):
                    continue
                msg = self._fetch_raw(mail, uid)
                self._restore_primary(mail)
                if not msg:
                    continue
                msg_id = msg.get("Message-ID", "").strip()
                if msg_id and msg_id not in collected:
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
            subject=msg.get("Subject", "(no subject)"),
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

            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
            save_path = subdir / f"uid_{uid}_{safe_name}"

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
            elif ext in ['.xlsx', '.xls']:
                df  = pd.read_excel(filepath, nrows=10)
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
            subject    = msg.get("Subject", "(no subject)")
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
            lines.append(f"\n{tm.body}")

            if tm.attachments:
                lines.append(f"\n  → {len(tm.attachments)} attachment(s) in this message:")
                for att in tm.attachments:
                    lines.append(f"     • {att.filename}")

        # ── Consolidated attachment section ──
        all_attachments = [att for tm in record.thread for att in tm.attachments]
        lines.append(f"\n{'='*60}")
        if all_attachments:
            lines.append(f"=== ALL ATTACHMENTS IN THREAD ({len(all_attachments)} total) ===")
            for att in all_attachments:
                lines.append(f"\n── File: {att.filename} ──")
                lines.append(f"   Sent by: {att.from_sender}")
                lines.append(f"   Date:    {att.email_date}")
                lines.append(f"   Preview:\n{att.preview[:1200]}")
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

        section_guide = (
            "Output ONLY clean Markdown. CRITICAL RULES:\n"
            "1. OMIT any section entirely if it has nothing to say — do NOT write 'None mentioned' or leave it blank.\n"
            "2. In the Attachment Summary, do NOT include the date the attachment was sent. "
               "Just state: filename, who sent it, what it contains, and why it matters.\n"
            "3. Use exactly these section headers (## prefix), and only include the ones with real content:\n\n"
            "## Thread Context\n"
            "What was the conversation history leading up to the new email(s)? "
            "Who said what? Omit entirely if standalone.\n\n"
            "## Executive Summary\n"
            "What is this person communicating in their latest message(s)?\n\n"
            "## Main Topics\n"
            "Key subjects discussed across the thread(s).\n\n"
            "## New Developments\n"
            "What is new or changed compared to prior messages.\n\n"
            "## Action Items / Asks\n"
            "Anything requested of you or others, explicit or implicit. Omit if none.\n\n"
            "## Deadlines / Dates / Meetings\n"
            "All time-sensitive items. Omit if none.\n\n"
            "## Risks / Things to Watch\n"
            "Issues or concerns raised. Omit if none.\n\n"
            "## Attachment Summary\n"
            "For EVERY attachment: filename, who sent it, what it contains, why it matters. "
            "No dates. Omit section if no attachments.\n\n"
            "## Bottom Line\n"
            "2-3 sentences in plain English: what do I need to know and what do I need to do?\n"
        )

        full_input = preamble + data_block + "\n\n" + section_guide

        try:
            response = self.openai_client.responses.create(
                model=self.model,
                instructions=instructions,
                input=full_input,
                temperature=0.0,
                max_output_tokens=4000,
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
        subject      = f"📬 Weekly Email Summary — {display_date}"
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
            run_date_display = now.strftime("%Y-%m-%d %-I:%M %p PST")  # e.g. 2026-04-07 1:40 PM PST

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
            master_md = f"# Master Weekly Summary — {run_date_display}\n\n"
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
    summarizer = EmailSummarizer(Path("email_summaries_output"))
    summarizer.run(days_back=int(os.getenv("DAYS_BACK", 7)))
