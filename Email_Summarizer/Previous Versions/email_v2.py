import os
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set
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

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class AttachmentInfo:
    filename: str
    saved_path: str
    preview: str

@dataclass
class EmailRecord:
    uid: int
    message_id: str
    sender: str
    subject: str
    date: str  # ISO format
    body: str
    attachments: List[AttachmentInfo]
    raw_path: Optional[str] = None
    # Thread context: ordered list of prior emails in the same thread (oldest first)
    thread_context: List[Dict] = field(default_factory=list)

class EmailSummarizer:
    def __init__(self, output_base: Path):
        self.output_base = Path(output_base)
        self.raw_dir = self.output_base / "raw_emails"
        self.attachments_dir = self.output_base / "attachments"
        self.summaries_dir = self.output_base / "summaries"
        self.json_dir = self.output_base / "json"
        
        for d in [self.raw_dir, self.attachments_dir, self.summaries_dir, self.json_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        self.state_file = self.output_base / "processed_state.json"
        self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        
        # Whitelist: comma-separated emails
        self.whitelist = [e.strip().lower() for e in os.getenv("WHITELIST_SENDERS", "").split(",") if e.strip()]
        if not self.whitelist:
            logger.warning("No whitelist senders defined in WHITELIST_SENDERS env var!")

    # ──────────────────────────────────────────────
    # State persistence
    # ──────────────────────────────────────────────

    def load_processed_uids(self) -> Set[int]:
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return set(data.get("processed_uids", []))
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return set()

    def save_processed_uids(self, uids: Set[int]):
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump({"processed_uids": sorted(list(uids)), "last_run": datetime.now().isoformat()}, f, indent=2)
            logger.info(f"Saved state with {len(uids)} processed UIDs")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    # ──────────────────────────────────────────────
    # IMAP connection + fetch
    # ──────────────────────────────────────────────

    def connect_imap(self) -> imaplib.IMAP4_SSL:
        server = os.getenv("IMAP_SERVER")
        port = int(os.getenv("IMAP_PORT", 993))
        user = os.getenv("IMAP_USER")
        password = os.getenv("IMAP_PASSWORD")
        folder = os.getenv("IMAP_FOLDER", "INBOX")
        
        if not all([server, user, password]):
            raise ValueError("Missing IMAP credentials in environment variables.")
        
        logger.info(f"Connecting to {server}:{port}")
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        mail.select(folder)
        logger.info(f"Selected folder: {folder}")
        return mail

    def fetch_emails(self, mail: imaplib.IMAP4_SSL, days_back: int = 7, processed_uids: Set[int] = None) -> List[Message]:
        if processed_uids is None:
            processed_uids = set()
        
        since_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        logger.info(f"Searching for emails since {since_date} from whitelisted senders only")
        
        if not self.whitelist:
            logger.warning("No whitelist defined - falling back to all emails")
            _, data = mail.uid('SEARCH', None, 'SINCE', since_date)
        else:
            search_terms = [f'FROM "{sender}"' for sender in self.whitelist]
            if len(search_terms) == 1:
                full_query = f'(SINCE {since_date} {search_terms[0]})'
            else:
                or_query = search_terms[0]
                for term in search_terms[1:]:
                    or_query = f'(OR {or_query} {term})'
                full_query = f'(SINCE {since_date} {or_query})'
            
            logger.info(f"Using targeted search for {len(self.whitelist)} whitelisted sender(s)")
            _, data = mail.uid('SEARCH', None, full_query)
        
        uid_list = data[0].split() if data and data[0] else []
        emails = []
        
        for uid_bytes in uid_list:
            uid = int(uid_bytes)
            if uid in processed_uids:
                continue
            try:
                _, msg_data = mail.uid('FETCH', str(uid), '(RFC822)')
                if msg_data and msg_data[0]:
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    msg.uid = uid
                    emails.append(msg)
            except Exception as e:
                logger.error(f"Error fetching UID {uid}: {e}")
        
        logger.info(f"Fetched {len(emails)} new emails from whitelisted contacts")
        return emails

    # ──────────────────────────────────────────────
    # Thread reconstruction
    # ──────────────────────────────────────────────

    def _extract_thread_message_ids(self, msg: Message) -> Set[str]:
        """
        Collect all Message-IDs referenced in this email's thread headers.
        Includes In-Reply-To and the full References chain.
        """
        ids: Set[str] = set()

        in_reply_to = msg.get("In-Reply-To", "").strip()
        if in_reply_to:
            ids.add(in_reply_to)

        references = msg.get("References", "").strip()
        if references:
            for ref in references.split():
                ref = ref.strip()
                if ref:
                    ids.add(ref)

        return ids

    def _fetch_message_by_id(self, mail: imaplib.IMAP4_SSL, message_id: str) -> Optional[Message]:
        """Search IMAP for a specific Message-ID and return the parsed message."""
        try:
            # IMAP HEADER search for Message-ID
            search_query = f'HEADER Message-ID "{message_id}"'
            _, data = mail.uid('SEARCH', None, search_query)
            uid_list = data[0].split() if data and data[0] else []

            if not uid_list:
                return None

            uid = int(uid_list[0])
            _, msg_data = mail.uid('FETCH', str(uid), '(RFC822)')
            if msg_data and msg_data[0]:
                raw_email = msg_data[0][1]
                parsed = email.message_from_bytes(raw_email)
                parsed.uid = uid
                return parsed
        except Exception as e:
            logger.warning(f"Could not fetch Message-ID {message_id}: {e}")
        return None

    def _fetch_full_thread(self, mail: imaplib.IMAP4_SSL, msg: Message) -> List[Dict]:
        """Improved thread fetching with stronger subject fallback"""
        thread_entries = []
        own_message_id = msg.get("Message-ID", "").strip()
        referenced_ids = self._extract_thread_message_ids(msg)

        logger.info(f"Starting thread fetch for UID {getattr(msg, 'uid', '?')} - Subject: {msg.get('Subject', '')[:80]}")
        logger.info(f"Referenced Message-IDs found: {len(referenced_ids)}")

        # Try referenced Message-IDs first
        for mid in referenced_ids:
            if mid == own_message_id:
                continue
            prior_msg = self._fetch_message_by_id(mail, mid)
            if prior_msg:
                thread_entries.append(self._msg_to_thread_entry(prior_msg, mail))
                logger.info(f"Found prior message via References: {prior_msg.get('Subject', '')[:60]}")

        # Stronger subject fallback — this usually catches most Gmail threads
        subject = msg.get("Subject", "")
        if subject:
            clean_subject = subject
            for prefix in ["Re:", "RE:", "Fwd:", "FWD:", "re:", "fwd:"]:
                clean_subject = clean_subject.replace(prefix, "").strip()
            
            try:
                _, data = mail.uid('SEARCH', None, f'SUBJECT "{clean_subject}"')
                uid_list = data[0].split() if data and data[0] else []
                logger.info(f"Subject fallback found {len(uid_list)} potential messages")

                for uid_bytes in uid_list:
                    uid = int(uid_bytes)
                    if uid == getattr(msg, 'uid', None):
                        continue
                    _, msg_data = mail.uid('FETCH', str(uid), '(RFC822)')
                    if msg_data and msg_data[0]:
                        candidate = email.message_from_bytes(msg_data[0][1])
                        candidate.uid = uid
                        cid = candidate.get("Message-ID", "").strip()
                        if cid and cid != own_message_id:
                            # Avoid duplicates
                            if not any(t.get("message_id") == cid for t in thread_entries):
                                entry = self._msg_to_thread_entry(candidate, mail)
                                thread_entries.append(entry)
                                logger.info(f"Added prior message via subject fallback: {candidate.get('Subject', '')[:60]}")
            except Exception as e:
                logger.warning(f"Subject fallback search failed: {e}")

        # Sort oldest first
        thread_entries.sort(key=lambda x: x.get("date", ""))
        
        logger.info(f"Successfully fetched {len(thread_entries)} prior messages in thread")
        return thread_entries

    def _msg_to_thread_entry(self, msg: Message, mail: imaplib.IMAP4_SSL) -> Dict:
        """Convert message to dict AND process its attachments."""
        sender = email.utils.parseaddr(msg.get("From", ""))[1].lower()
        date_str = msg.get("Date", "")
        try:
            date_iso = email.utils.parsedate_to_datetime(date_str).isoformat()
        except Exception:
            date_iso = datetime.now().isoformat()

        body = self.extract_body(msg, strip_reply_chain=False)

        # Process attachments from this historical email in the thread
        attachments = []
        uid = getattr(msg, 'uid', 0)
        if uid:
            attachments_subdir = self.attachments_dir / f"email_{uid}"
            attachments_subdir.mkdir(exist_ok=True)
            
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                disposition = str(part.get("Content-Disposition", "")).lower()
                if "attachment" in disposition or part.get_filename():
                    att = self.process_attachment(part, attachments_subdir, uid)
                    if att:
                        attachments.append({
                            "filename": att.filename,
                            "preview": att.preview[:600]
                        })

        return {
            "message_id": msg.get("Message-ID", "").strip(),
            "sender": sender,
            "subject": msg.get("Subject", "(no subject)"),
            "date": date_iso,
            "body": body,
            "attachments": attachments
        }

    # ──────────────────────────────────────────────
    # Body extraction
    # ──────────────────────────────────────────────

    def extract_body(self, msg: Message, strip_reply_chain: bool = True) -> str:
        """Extract cleaned body. Prefer plain text; fallback to HTML-to-text.
        
        strip_reply_chain=True  → used for new/trigger emails: cuts quoted history
                                   so it doesn't duplicate what we fetch separately.
        strip_reply_chain=False → used for thread-history emails: preserves full body
                                   so nothing gets silently dropped.
        """
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if "attachment" in str(part.get("Content-Disposition", "")).lower():
                    continue
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='replace')
                        break
                elif content_type == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html = payload.decode('utf-8', errors='replace')
                        h = html2text.HTML2Text()
                        h.ignore_links = True
                        h.ignore_images = True
                        body = h.handle(html)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == "text/html":
                    html = payload.decode('utf-8', errors='replace')
                    h = html2text.HTML2Text()
                    h.ignore_links = True
                    h.ignore_images = True
                    body = h.handle(html)
                else:
                    body = payload.decode('utf-8', errors='replace')
        
        if strip_reply_chain:
            # For the triggering email: strip quoted history to avoid duplication
            # (the prior messages are fetched separately as thread context)
            lines = body.splitlines()
            cleaned = []
            for line in lines:
                lower = line.lower().strip()
                if any(marker in lower for marker in ["-----original message-----", "on ", "wrote:", "from:", "sent:", "to:", "subject:"]):
                    break
                cleaned.append(line)
            body = '\n'.join(cleaned).strip()
        
        if len(body) > 12000:
            body = body[:12000] + "\n... [body truncated for summary]"
        return body

    # ──────────────────────────────────────────────
    # Attachments
    # ──────────────────────────────────────────────

    def process_attachment(self, part: Message, attachments_dir: Path, email_uid: int) -> Optional[AttachmentInfo]:
        filename = part.get_filename()
        if not filename:
            return None
        
        safe_filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
        save_path = attachments_dir / f"uid_{email_uid}_{safe_filename}"
        
        try:
            payload = part.get_payload(decode=True)
            if payload and len(payload) < 10 * 1024 * 1024:
                with open(save_path, "wb") as f:
                    f.write(payload)
                logger.info(f"Saved attachment: {save_path.name}")
                preview = self.generate_attachment_preview(save_path, filename)
                return AttachmentInfo(filename=filename, saved_path=str(save_path), preview=preview or "No preview generated.")
            elif payload:
                logger.warning(f"Skipped large attachment (>10MB): {filename}")
                return AttachmentInfo(filename=filename, saved_path=str(save_path), preview="Attachment too large for preview.")
        except Exception as e:
            logger.error(f"Error processing attachment {filename}: {e}")
            return AttachmentInfo(filename=filename, saved_path="", preview=f"Error processing: {str(e)}")
        
        return None

    def generate_attachment_preview(self, filepath: Path, filename: str) -> str:
        ext = filepath.suffix.lower()
        try:
            if ext in ['.csv', '.tsv']:
                sep = '\t' if ext == '.tsv' else ','
                df = pd.read_csv(filepath, sep=sep, nrows=10, on_bad_lines='skip')
                preview = f"CSV/TSV: {len(df)} rows, {len(df.columns)} cols. Columns: {list(df.columns[:10])}\n"
                preview += f"Preview:\n{df.head(3).to_string(index=False)}\n"
                return preview[:1500]
            elif ext in ['.xlsx', '.xls']:
                df = pd.read_excel(filepath, nrows=10)
                preview = f"Excel: {len(df)} rows, {len(df.columns)} cols. Columns: {list(df.columns[:10])}\n"
                preview += f"Preview:\n{df.head(3).to_string(index=False)}\n"
                return preview[:1500]
            elif ext == '.pdf':
                reader = PdfReader(filepath)
                text = ""
                for page in reader.pages[:3]:
                    text += (page.extract_text() or "") + "\n"
                text = text[:2000].strip()
                return f"PDF (first pages): {text}" if text else "PDF: No extractable text."
            elif ext in ['.docx', '.doc']:
                doc = Document(filepath)
                text = "\n".join([para.text.strip() for para in doc.paragraphs if para.text.strip()])
                text = text[:2000]
                return f"DOCX text preview: {text}" if text else "DOCX: No text extractable."
            elif ext in ['.txt', '.md', '.log']:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    text = f.read(2000)
                return f"Text file preview: {text}"
            else:
                return "Non-text attachment saved (no preview generated)."
        except Exception as e:
            logger.warning(f"Preview generation failed for {filename}: {e}")
            return f"Preview failed: {str(e)[:100]}"

    # ──────────────────────────────────────────────
    # Email parsing (now with thread fetch)
    # ──────────────────────────────────────────────

    def parse_email(self, msg: Message, mail: imaplib.IMAP4_SSL) -> Optional[EmailRecord]:
        try:
            uid = getattr(msg, 'uid', 0)
            message_id = msg.get("Message-ID", "")
            sender = email.utils.parseaddr(msg.get("From", ""))[1].lower()
            subject = msg.get("Subject", "(no subject)")
            date_str = msg.get("Date", "")
            try:
                date_obj = email.utils.parsedate_to_datetime(date_str)
                date_iso = date_obj.isoformat()
            except Exception:
                date_iso = datetime.now().isoformat()
            
            body = self.extract_body(msg)
            
            raw_path = self.raw_dir / f"uid_{uid}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(f"Subject: {subject}\nFrom: {sender}\nDate: {date_iso}\n\n{body}")
            
            # Attachments
            attachments = []
            attachments_subdir = self.attachments_dir / f"email_{uid}"
            attachments_subdir.mkdir(exist_ok=True)
            
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                disposition = str(part.get("Content-Disposition", "")).lower()
                if "attachment" in disposition or part.get_filename():
                    att = self.process_attachment(part, attachments_subdir, uid)
                    if att:
                        attachments.append(att)

            # ── Thread context ──
            thread_context = []
            is_reply = bool(msg.get("In-Reply-To") or msg.get("References"))
            if is_reply:
                logger.info(f"Email UID {uid} is part of a thread — fetching full chain...")
                thread_context = self._fetch_full_thread(mail, msg)
            
            return EmailRecord(
                uid=uid,
                message_id=message_id,
                sender=sender,
                subject=subject,
                date=date_iso,
                body=body,
                attachments=attachments,
                raw_path=str(raw_path),
                thread_context=thread_context,
            )
        except Exception as e:
            logger.error(f"Error parsing email UID {getattr(msg, 'uid', 'unknown')}: {e}")
            return None

    # ──────────────────────────────────────────────
    # Grouping
    # ──────────────────────────────────────────────

    def group_emails_by_sender(self, emails: List[EmailRecord]) -> Dict[str, List[EmailRecord]]:
        from collections import defaultdict
        groups = defaultdict(list)
        for rec in emails:
            if rec and rec.sender.lower() in self.whitelist:
                groups[rec.sender].append(rec)
        return groups

    # ──────────────────────────────────────────────
    # Summary generation
    # ──────────────────────────────────────────────

    def _format_thread_context(self, thread_context: List[Dict]) -> str:
        """Render thread history as a readable block for the LLM prompt."""
        if not thread_context:
            return ""
        lines = ["── PRIOR THREAD HISTORY (oldest → newest) ──"]
        for i, entry in enumerate(thread_context, 1):
            participants = f"From: {entry['sender']}"
            if entry.get("to"):
                participants += f"  |  To: {entry['to']}"
            if entry.get("cc"):
                participants += f"  |  CC: {entry['cc']}"
            lines.append(
                f"\n[{i}] {entry['date']} — {entry['subject']}\n"
                f"{participants}\n"
                f"{entry['body'][:3000]}"
                + (" ... [truncated]" if len(entry['body']) > 3000 else "")
            )
        lines.append("── END OF THREAD HISTORY ──")
        return "\n".join(lines)

    def generate_summary(self, emails: List[EmailRecord], contact_name: Optional[str] = None, is_overall: bool = False) -> str:
        if not emails:
            return "No emails to summarize."
        
        context_parts = []
        for e in emails:
            att_summary = "\n".join([f"• {a.filename}: {a.preview[:400]}..." for a in e.attachments]) if e.attachments else "No attachments."

            # Prepend thread history if present
            thread_block = ""
            if e.thread_context:
                thread_block = self._format_thread_context(e.thread_context)
                thread_block = f"\n{thread_block}\n\n"

            context_parts.append(f"""
{thread_block}── NEW EMAIL ──
Date: {e.date}
Subject: {e.subject}
From: {e.sender}
Body:
{e.body}

Attachments:
{att_summary}
---""")
        
        data_block = "\n".join(context_parts)
        
        if is_overall:
            instructions = "You are an executive business analyst generating a master overview across multiple key contacts."
            input_text = f"OVERALL WEEKLY SUMMARY REQUEST\n\n{data_block}\n\nSynthesize into one master report."
        else:
            instructions = f"You are a precise business analyst summarizing emails from contact: {contact_name}"
            input_text = f"CONTACT SUMMARY REQUEST for {contact_name}\n\n{data_block}"
        
        full_input = (
            f"{instructions}\n\n{input_text}\n\n"
            "Output ONLY in clean Markdown with these exact sections (be factual, conservative, note uncertainties):\n"
            "• Thread Context  ← summarize the prior conversation history ONLY if this email is part of a thread; omit section if standalone\n"
            "• Executive Summary\n"
            "• Main Recurring Topics\n"
            "• Important New Developments\n"
            "• Action Items / Asks\n"
            "• Deadlines / Dates / Meetings\n"
            "• Risks / Issues / Things to Watch\n"
            "• Attachment/Data Highlights\n"
            "• Bottom Line (plain English)"
        )
        
        try:
            response = self.openai_client.responses.create(
                model=self.model,
                instructions=instructions,
                input=full_input,
                temperature=0.0,
                max_output_tokens=4000
            )
            summary = response.output_text
            logger.info(f"✅ Generated {'overall' if is_overall else 'contact'} summary")
            return summary
        except Exception as e:
            logger.error(f"OpenAI Responses API error: {e}")
            return f"Summary generation failed: {str(e)}"

    # ──────────────────────────────────────────────
    # Main pipeline
    # ──────────────────────────────────────────────

    def run(self, days_back: int = 7):
        processed_uids = self.load_processed_uids()
        mail = self.connect_imap()
        
        try:
            raw_msgs = self.fetch_emails(mail, days_back, processed_uids)
            email_records: List[EmailRecord] = []
            new_uids: Set[int] = set()
            
            run_date = datetime.now().strftime("%Y-%m-%d_%H%M")
            run_dir = self.output_base / run_date
            run_dir.mkdir(exist_ok=True)
            
            for msg in raw_msgs:
                # Pass the live mail connection so thread fetching can happen inline
                record = self.parse_email(msg, mail)
                if record:
                    email_records.append(record)
                    new_uids.add(record.uid)
            
            if not email_records:
                logger.info("No new emails from whitelisted contacts this run.")
                return
            
            groups = self.group_emails_by_sender(email_records)
            logger.info(f"Processed {len(email_records)} emails from {len(groups)} whitelisted contact(s).")
            
            # Per-contact summaries
            for sender, recs in groups.items():
                summary = self.generate_summary(recs, sender)
                safe_sender = sender.replace("@", "_at_").replace(".", "_")
                with open(self.summaries_dir / f"{safe_sender}_{run_date}.md", "w", encoding="utf-8") as f:
                    f.write(f"# Summary for {sender}\n\n{summary}")
            
            # Overall master summary
            overall_summary = self.generate_summary(email_records, is_overall=True)
            with open(self.summaries_dir / f"OVERALL_MASTER_{run_date}.md", "w", encoding="utf-8") as f:
                f.write(f"# Master Overall Summary — {run_date}\n\n{overall_summary}")
            
            # JSON export
            json_path = self.json_dir / f"emails_{run_date}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([asdict(e) for e in email_records], f, indent=2, default=str)
            
            processed_uids.update(new_uids)
            self.save_processed_uids(processed_uids)
            
            logger.info("✅ Pipeline completed successfully.")
            
        finally:
            try:
                mail.close()
                mail.logout()
            except Exception:
                pass


if __name__ == "__main__":
    output_base = Path("email_summaries_output")
    summarizer = EmailSummarizer(output_base)
    summarizer.run(days_back=int(os.getenv("DAYS_BACK", 7)))