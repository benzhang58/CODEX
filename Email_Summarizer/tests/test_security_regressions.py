import base64
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"] = "/tmp/discere-test-storage"
os.environ["EMAIL_SUMMARIZER_OUTPUT_DIR"] = "/tmp/discere-test-output"
os.environ["EMAIL_SUMMARIZER_PUBLIC_BASE_URL"] = "https://discere-test.example"
os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = "false"
os.environ["EMAIL_SUMMARIZER_ENCRYPTION_KEY"] = "test-only-encryption-key"
os.environ["OPENAI_API_KEY"] = "test-openai-key"
os.environ["WHITELIST_SENDERS"] = "should-not-leak@example.com"
os.environ["IMAP_USER"] = "global-imap@example.com"
os.environ["IMAP_PASSWORD"] = "global-imap-password"
os.environ["SMTP_USER"] = "global-smtp@example.com"
os.environ["SMTP_PASSWORD"] = "global-smtp-password"
os.environ["SUMMARY_RECIPIENT"] = "global-recipient@example.com"
os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = "100"
os.environ["EMAIL_SUMMARIZER_LIMIT_RUN_SUMMARIZER_PER_DAY"] = "10"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import dashboard_api


def make_unsigned_id_token(claims: dict) -> str:
    def encode(segment: dict) -> str:
        raw = json.dumps(segment, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    return f"{encode({'alg': 'none'})}.{encode(claims)}."


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"], ignore_errors=True)
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_OUTPUT_DIR"], ignore_errors=True)
        dashboard_api.initialize_database()
        self.client = TestClient(dashboard_api.app, base_url="https://discere-test.example")

    def signup(self, email: str) -> TestClient:
        client = TestClient(dashboard_api.app, base_url="https://discere-test.example")
        response = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "StrongPass123!",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return client

    def connect_standard_mailbox(self, client: TestClient, email: str) -> None:
        response = client.put(
            "/profile",
            json={
                "email": email,
                "imap_user": email,
                "imap_password": "MailboxPass123!",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["profile"]["settings"]["mailbox_connected"])

    def test_cookie_secure_defaults_on_for_https_public_base_url(self) -> None:
        self.assertTrue(dashboard_api.SESSION_COOKIE_SECURE)

    def test_home_redirects_to_dashboard_when_session_is_valid(self) -> None:
        client = self.signup("home-redirect@example.com")
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/dashboard")

    def test_home_stays_public_after_logout(self) -> None:
        client = self.signup("home-logout@example.com")
        logout_response = client.post("/auth/logout")
        self.assertEqual(logout_response.status_code, 200, logout_response.text)

        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)

    def test_google_oauth_start_requests_offline_consent_for_refresh_token(self) -> None:
        originals = {
            "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
            "GOOGLE_CLIENT_SECRET": os.environ.get("GOOGLE_CLIENT_SECRET"),
            "GOOGLE_REDIRECT_URI": os.environ.get("GOOGLE_REDIRECT_URI"),
        }
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-client"
        os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-secret"
        os.environ["GOOGLE_REDIRECT_URI"] = "https://discere-test.example/auth/google/callback"
        try:
            response = self.client.get("/auth/google/start", follow_redirects=False)
            self.assertEqual(response.status_code, 307, response.text)
            query = parse_qs(urlparse(response.headers["location"]).query)
            self.assertEqual(query.get("access_type"), ["offline"])
            self.assertEqual(query.get("prompt"), ["consent"])
            self.assertEqual(query.get("include_granted_scopes"), ["true"])
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_oauth_start_requests_outlook_imap_scope_without_graph_user_read(self) -> None:
        originals = {
            "MICROSOFT_CLIENT_ID": os.environ.get("MICROSOFT_CLIENT_ID"),
            "MICROSOFT_CLIENT_SECRET": os.environ.get("MICROSOFT_CLIENT_SECRET"),
            "MICROSOFT_REDIRECT_URI": os.environ.get("MICROSOFT_REDIRECT_URI"),
            "MICROSOFT_TENANT_ID": os.environ.get("MICROSOFT_TENANT_ID"),
        }
        os.environ["MICROSOFT_CLIENT_ID"] = "test-microsoft-client"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "test-microsoft-secret"
        os.environ["MICROSOFT_REDIRECT_URI"] = "https://discere-test.example/auth/microsoft/callback"
        os.environ["MICROSOFT_TENANT_ID"] = "common"
        try:
            response = self.client.get("/auth/microsoft/start", follow_redirects=False)
            self.assertEqual(response.status_code, 307, response.text)
            query = parse_qs(urlparse(response.headers["location"]).query)
            scopes = query.get("scope", [""])[0].split()
            self.assertIn(dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE, scopes)
            self.assertNotIn("User.Read", scopes)
            self.assertEqual(query.get("prompt"), ["consent"])
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_oauth_callback_uses_id_token_without_graph_userinfo(self) -> None:
        originals = {
            "MICROSOFT_CLIENT_ID": os.environ.get("MICROSOFT_CLIENT_ID"),
            "MICROSOFT_CLIENT_SECRET": os.environ.get("MICROSOFT_CLIENT_SECRET"),
            "MICROSOFT_REDIRECT_URI": os.environ.get("MICROSOFT_REDIRECT_URI"),
            "MICROSOFT_TENANT_ID": os.environ.get("MICROSOFT_TENANT_ID"),
        }
        os.environ["MICROSOFT_CLIENT_ID"] = "test-microsoft-client"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "test-microsoft-secret"
        os.environ["MICROSOFT_REDIRECT_URI"] = "https://discere-test.example/auth/microsoft/callback"
        os.environ["MICROSOFT_TENANT_ID"] = "common"
        try:
            start_response = self.client.get("/auth/microsoft/start", follow_redirects=False)
            state = parse_qs(urlparse(start_response.headers["location"]).query)["state"][0]
            id_token = make_unsigned_id_token(
                {
                    "preferred_username": "outlook-user@example.com",
                    "email": "outlook-user@example.com",
                    "name": "Outlook User",
                }
            )
            token_payload = {
                "access_token": "outlook-imap-access-token",
                "refresh_token": "outlook-refresh-token",
                "scope": dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE,
                "id_token": id_token,
            }
            with patch.object(dashboard_api, "post_form_json", return_value=token_payload), patch.object(
                dashboard_api,
                "get_json_with_bearer",
                side_effect=AssertionError("Microsoft callback should not call Graph /me"),
            ):
                response = self.client.get(
                    f"/auth/microsoft/callback?code=test-code&state={state}",
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 307, response.text)
            self.assertEqual(response.headers.get("location"), "/dashboard")
            profile = dashboard_api.load_profile_or_404("outlook_user_example_com")
            self.assertEqual(profile["email"], "outlook-user@example.com")
            self.assertEqual(profile["microsoft_oauth"]["access_token"], "outlook-imap-access-token")
            self.assertTrue(dashboard_api.microsoft_oauth_has_scope(profile, dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE))
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_refresh_consent_required_returns_clean_reconnect_error(self) -> None:
        client = self.signup("microsoft-consent@example.com")
        user_id = "microsoft_consent_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "microsoft-consent@example.com",
            "access_token": "old-access-token",
            "refresh_token": "old-refresh-token",
            "scope": dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE,
        }
        dashboard_api.save_profile(profile)

        originals = {
            "MICROSOFT_CLIENT_ID": os.environ.get("MICROSOFT_CLIENT_ID"),
            "MICROSOFT_CLIENT_SECRET": os.environ.get("MICROSOFT_CLIENT_SECRET"),
            "MICROSOFT_TENANT_ID": os.environ.get("MICROSOFT_TENANT_ID"),
        }
        os.environ["MICROSOFT_CLIENT_ID"] = "test-microsoft-client"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "test-microsoft-secret"
        os.environ["MICROSOFT_TENANT_ID"] = "common"
        try:
            with patch.object(
                dashboard_api,
                "post_form_json",
                side_effect=dashboard_api.HTTPException(
                    status_code=500,
                    detail='Microsoft token refresh failed: {"error":"invalid_grant","suberror":"consent_required","error_codes":[65001]}',
                ),
            ):
                response = client.post("/run-summarizer", json={"days_back": 7})

            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn("Microsoft mailbox access needs approval", response.json()["detail"])
            self.assertEqual(response.headers.get("X-Discere-Reconnect-Provider"), "microsoft")
            self.assertIn("/auth/microsoft/start?", response.headers.get("X-Discere-Reconnect-Url", ""))
            self.assertIn("force_reconsent=true", response.headers.get("X-Discere-Reconnect-Url", ""))
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_force_reconsent_clears_stale_oauth_before_redirect(self) -> None:
        client = self.signup("stale-microsoft@example.com")
        user_id = "stale_microsoft_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "stale-microsoft@example.com",
            "access_token": "stale-access",
            "refresh_token": "stale-refresh",
            "scope": dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE,
        }
        dashboard_api.save_profile(profile)

        originals = {
            "MICROSOFT_CLIENT_ID": os.environ.get("MICROSOFT_CLIENT_ID"),
            "MICROSOFT_CLIENT_SECRET": os.environ.get("MICROSOFT_CLIENT_SECRET"),
            "MICROSOFT_REDIRECT_URI": os.environ.get("MICROSOFT_REDIRECT_URI"),
            "MICROSOFT_TENANT_ID": os.environ.get("MICROSOFT_TENANT_ID"),
        }
        os.environ["MICROSOFT_CLIENT_ID"] = "test-microsoft-client"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "test-microsoft-secret"
        os.environ["MICROSOFT_REDIRECT_URI"] = "https://discere-test.example/auth/microsoft/callback"
        os.environ["MICROSOFT_TENANT_ID"] = "common"
        try:
            response = client.get("/auth/microsoft/start?force_reconsent=true", follow_redirects=False)
            self.assertEqual(response.status_code, 307, response.text)
            query = parse_qs(urlparse(response.headers["location"]).query)
            self.assertEqual(query.get("prompt"), ["consent"])
            refreshed = dashboard_api.load_profile_or_404(user_id)
            self.assertFalse(refreshed.get("microsoft_oauth"))
            self.assertEqual(refreshed["settings"].get("MAILBOX_CONNECTION_CONFIRMED"), "false")
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_existing_google_session_refreshes_mailbox_token_before_run(self) -> None:
        client = self.signup("remembered-gmail@gmail.com")
        user_id = "remembered_gmail_gmail_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["google_oauth"] = {
            "provider": "google",
            "email": "remembered-gmail@gmail.com",
            "access_token": "expired-access-token",
            "refresh_token": "stored-refresh-token",
            "scope": dashboard_api.REQUIRED_GOOGLE_READ_SCOPE,
        }
        dashboard_api.save_profile(profile)

        originals = {
            "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
            "GOOGLE_CLIENT_SECRET": os.environ.get("GOOGLE_CLIENT_SECRET"),
        }
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-client"
        os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-secret"
        try:
            with patch.object(dashboard_api, "post_form_json", return_value={"access_token": "fresh-access-token"}), patch.object(
                dashboard_api,
                "launch_summarizer_job",
                return_value={"job_id": "job-google", "status": "running", "user_id": user_id},
            ) as launch_mock:
                response = client.post("/run-summarizer", json={"days_back": 7})

            self.assertEqual(response.status_code, 200, response.text)
            launch_mock.assert_called_once()
            refreshed = dashboard_api.load_profile_or_404(user_id)
            self.assertEqual(refreshed["google_oauth"].get("access_token"), "fresh-access-token")
            self.assertEqual(refreshed["google_oauth"].get("refresh_token"), "stored-refresh-token")
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_existing_microsoft_session_refreshes_mailbox_token_before_run(self) -> None:
        client = self.signup("remembered-outlook@example.com")
        user_id = "remembered_outlook_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "remembered-outlook@example.com",
            "access_token": "expired-access-token",
            "refresh_token": "stored-refresh-token",
            "scope": dashboard_api.REQUIRED_MICROSOFT_IMAP_SCOPE,
        }
        dashboard_api.save_profile(profile)

        originals = {
            "MICROSOFT_CLIENT_ID": os.environ.get("MICROSOFT_CLIENT_ID"),
            "MICROSOFT_CLIENT_SECRET": os.environ.get("MICROSOFT_CLIENT_SECRET"),
            "MICROSOFT_TENANT_ID": os.environ.get("MICROSOFT_TENANT_ID"),
        }
        os.environ["MICROSOFT_CLIENT_ID"] = "test-microsoft-client"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "test-microsoft-secret"
        os.environ["MICROSOFT_TENANT_ID"] = "common"
        try:
            with patch.object(
                dashboard_api,
                "post_form_json",
                return_value={"access_token": "fresh-access-token", "refresh_token": "rotated-refresh-token"},
            ), patch.object(
                dashboard_api,
                "launch_summarizer_job",
                return_value={"job_id": "job-microsoft", "status": "running", "user_id": user_id},
            ) as launch_mock:
                response = client.post("/run-summarizer", json={"days_back": 7})

            self.assertEqual(response.status_code, 200, response.text)
            launch_mock.assert_called_once()
            refreshed = dashboard_api.load_profile_or_404(user_id)
            self.assertEqual(refreshed["microsoft_oauth"].get("access_token"), "fresh-access-token")
            self.assertEqual(refreshed["microsoft_oauth"].get("refresh_token"), "rotated-refresh-token")
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_new_accounts_do_not_inherit_global_account_scoped_settings(self) -> None:
        client = self.signup("fresh@example.com")
        response = client.get("/whitelist")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["contacts"], [])

        profile_response = client.get("/auth/me")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        payload = profile_response.json()["profile"]
        settings = payload["settings"]
        self.assertEqual(settings.get("imap_user"), "fresh@example.com")
        self.assertNotIn("smtp_user", settings)
        self.assertNotIn("summary_recipient", settings)
        self.assertNotIn("global-imap@example.com", json.dumps(payload))
        self.assertNotIn("global-smtp@example.com", json.dumps(payload))
        self.assertNotIn("global-recipient@example.com", json.dumps(payload))
        self.assertNotIn("should-not-leak@example.com", json.dumps(payload))

    def test_password_signup_does_not_auto_connect_mailbox_with_dashboard_password(self) -> None:
        client = self.signup("standard-mailbox@example.com")
        profile_response = client.get("/auth/me")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        payload = profile_response.json()["profile"]
        self.assertFalse(payload["settings"]["mailbox_connected"])

        status_response = client.get("/mailbox/status")
        self.assertEqual(status_response.status_code, 200, status_response.text)
        self.assertFalse(status_response.json()["connected"])
        self.assertEqual(status_response.json()["reason"], "missing_credentials")

    def test_failed_password_mailbox_status_clears_connected_flag(self) -> None:
        client = self.signup("bad-mailbox@example.com")
        self.connect_standard_mailbox(client, "bad-mailbox@example.com")

        class BadMailbox:
            def login(self, email: str, password: str) -> None:
                raise RuntimeError("bad credentials")

            def shutdown(self) -> None:
                return None

        with patch.object(dashboard_api.imaplib, "IMAP4_SSL", return_value=BadMailbox()):
            status_response = client.get("/mailbox/status")

        self.assertEqual(status_response.status_code, 200, status_response.text)
        self.assertFalse(status_response.json()["connected"])
        self.assertEqual(status_response.json()["reason"], "login_failed")

        profile_response = client.get("/auth/me")
        self.assertFalse(profile_response.json()["profile"]["settings"]["mailbox_connected"])

    def test_password_account_cannot_run_summarizer_until_mailbox_is_connected(self) -> None:
        client = self.signup("needs-mailbox@example.com")
        whitelist_response = client.post("/whitelist", json={"contacts": ["sender@example.com"]})
        self.assertEqual(whitelist_response.status_code, 200, whitelist_response.text)

        response = client.post("/run-summarizer", json={"days_back": 7})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Mailbox is not connected yet", response.json()["detail"])

        result = dashboard_api.execute_summarizer_run("needs_mailbox_example_com", 7)
        self.assertFalse(result["success"])
        self.assertIn("Mailbox is not connected yet", result["stderr"])

    def test_password_account_cannot_create_schedule_until_mailbox_is_connected(self) -> None:
        client = self.signup("schedule-needs-mailbox@example.com")
        response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Mailbox is not connected yet", response.json()["detail"])

    def test_invalid_contact_email_is_rejected(self) -> None:
        client = self.signup("invalid-contact@example.com")
        response = client.post("/whitelist", json={"contacts": ["not-an-email"]})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["detail"], "Incorrect email.")

    def test_cross_account_user_id_override_is_blocked(self) -> None:
        alice = self.signup("alice@example.com")
        bob = self.signup("bob@example.com")

        response = alice.post(
            "/whitelist",
            json={"user_id": "alice_example_com", "contacts": ["a@sender.com"]},
        )
        self.assertEqual(response.status_code, 200, response.text)

        response = bob.get("/whitelist")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["contacts"], [])

        response = bob.get("/whitelist", params={"user_id": "alice_example_com"})
        self.assertEqual(response.status_code, 403, response.text)

    def test_cross_account_summary_and_attachment_access_is_blocked(self) -> None:
        alice = self.signup("summary-alice@example.com")
        bob = self.signup("summary-bob@example.com")
        alice_user_id = "summary_alice_example_com"
        bob_user_id = "summary_bob_example_com"

        alice_summary_dir = dashboard_api.get_user_json_summaries_dir(alice_user_id)
        alice_summary_dir.mkdir(parents=True, exist_ok=True)
        (alice_summary_dir / "secret.json").write_text(
            json.dumps(
                {
                    "summary_id": "secret",
                    "sender": "boss@example.com",
                    "title": "Private Alice summary",
                    "executive_summary": "Alice-only content",
                }
            ),
            encoding="utf-8",
        )

        alice_attachment_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / alice_user_id / "attachments"
        alice_attachment_dir.mkdir(parents=True, exist_ok=True)
        alice_attachment = alice_attachment_dir / "private.txt"
        alice_attachment.write_text("alice private attachment", encoding="utf-8")

        response = alice.get("/summaries/secret")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Alice-only content", response.text)

        response = bob.get("/summaries/secret")
        self.assertEqual(response.status_code, 404, response.text)

        response = bob.get("/summaries/secret", params={"user_id": alice_user_id})
        self.assertEqual(response.status_code, 403, response.text)

        response = bob.get(
            "/attachments",
            params={"user_id": bob_user_id, "path": str(alice_attachment)},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_public_report_links_reject_path_traversal_even_with_valid_signature(self) -> None:
        user_id = "report_owner"
        private_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / user_id
        private_dir.mkdir(parents=True, exist_ok=True)
        private_file = private_dir / "private.pdf"
        private_file.write_bytes(b"%PDF-1.4 private")

        traversal_path = f"{user_id}/../users/{user_id}/private.pdf"
        expires = int((dashboard_api.datetime.now() + dashboard_api.timedelta(minutes=5)).timestamp())
        signature = dashboard_api.sign_public_report_token(user_id, traversal_path, expires)

        response = self.client.get(
            "/public-report",
            params={"user_id": user_id, "path": traversal_path, "expires": expires, "sig": signature},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_account_export_endpoint_is_not_available(self) -> None:
        client = self.signup("no-export@example.com")
        response = client.get("/auth/account/export")
        self.assertEqual(response.status_code, 404, response.text)

    def test_report_recipient_uses_connected_account_email(self) -> None:
        profile = {
            "email": "profile@example.com",
            "google_oauth": {"email": "google-account@example.com"},
            "microsoft_oauth": {"email": "microsoft-account@example.com"},
        }
        settings = {
            "IMAP_USER": "imap-mailbox@example.com",
            "SUMMARY_RECIPIENT": "old-custom-recipient@example.com",
        }
        self.assertEqual(dashboard_api.default_report_recipient(profile, settings), "google-account@example.com")

        manual_profile = {"email": "profile@example.com"}
        self.assertEqual(dashboard_api.default_report_recipient(manual_profile, settings), "imap-mailbox@example.com")

    def test_report_schedule_ignores_custom_recipient_email(self) -> None:
        client = self.signup("schedule-owner@example.com")
        self.connect_standard_mailbox(client, "schedule-owner@example.com")
        response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "recipient_email": "outside-recipient@example.com",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["schedule"]["recipient_email"], "schedule-owner@example.com")

    def test_profile_update_persists_report_email_mode(self) -> None:
        client = self.signup("report-mode@example.com")

        response = client.put(
            "/profile",
            json={"email": "report-mode@example.com", "report_email_mode": "private_notification"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["profile"]["settings"]["report_email_mode"], "private_notification")

        response = client.put(
            "/profile",
            json={"email": "report-mode@example.com", "report_email_mode": "unexpected-mode"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["profile"]["settings"]["report_email_mode"], "full_report")

    def test_private_report_email_mode_omits_summary_content(self) -> None:
        client = self.signup("private-report@example.com")
        response = client.put(
            "/profile",
            json={"email": "private-report@example.com", "report_email_mode": "private_notification"},
        )
        self.assertEqual(response.status_code, 200, response.text)

        secret_summary = {
            "summary_id": "secret_summary",
            "title": "Confidential merger update",
            "sender": "ceo@example.com",
            "executive_summary": "Acquire Project Falcon next Friday.",
            "bottom_line": "Do not leak this.",
        }
        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "private-report@example.com", "subject": "Your Discere summary is ready"},
        ) as send_mock:
            dashboard_api.send_summary_via_smtp("private_report_example_com", secret_summary)

        send_kwargs = send_mock.call_args.kwargs
        serialized = json.dumps(send_kwargs)
        self.assertEqual(send_kwargs["subject"], "Your Discere summary is ready")
        self.assertNotIn("Confidential merger update", serialized)
        self.assertNotIn("Acquire Project Falcon", serialized)
        self.assertNotIn("Do not leak this", serialized)
        self.assertIn("Private Notification", serialized)

    def test_private_combined_report_mode_omits_report_content(self) -> None:
        client = self.signup("private-combined@example.com")
        response = client.put(
            "/profile",
            json={"email": "private-combined@example.com", "report_email_mode": "private_notification"},
        )
        self.assertEqual(response.status_code, 200, response.text)

        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "private-combined@example.com", "subject": "Your Discere report is ready"},
        ) as send_mock:
            dashboard_api.send_combined_report_via_smtp(
                "private_combined_example_com",
                "Board acquisition report",
                "## Secret section\nProject Falcon closes Friday.",
            )

        send_kwargs = send_mock.call_args.kwargs
        serialized = json.dumps(send_kwargs)
        self.assertEqual(send_kwargs["subject"], "Your Discere report is ready")
        self.assertNotIn("Board acquisition report", serialized)
        self.assertNotIn("Project Falcon", serialized)
        self.assertIn("Private Notification", serialized)

    def test_new_accounts_start_with_no_card_free_trial(self) -> None:
        client = self.signup("trial@example.com")
        response = client.get("/billing/status")
        self.assertEqual(response.status_code, 200, response.text)
        subscription = response.json()["subscription"]
        self.assertEqual(subscription["status"], "trialing")
        self.assertFalse(subscription["requires_subscription"])
        self.assertEqual(subscription["price_cents"], 499)
        self.assertEqual(subscription["trial_days"], 7)
        self.assertNotIn("stripe_customer_id", subscription)
        self.assertNotIn("stripe_subscription_id", subscription)

    def test_expired_trial_blocks_paid_features_without_blocking_exempt_accounts(self) -> None:
        client = self.signup("expired@example.com")
        user_id = "expired_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["settings"]["SUBSCRIPTION_STATUS"] = "trialing"
        profile["settings"]["SUBSCRIPTION_TRIAL_STARTED_AT"] = (
            dashboard_api.datetime.now() - dashboard_api.timedelta(days=10)
        ).isoformat()
        profile["settings"]["SUBSCRIPTION_TRIAL_ENDS_AT"] = (
            dashboard_api.datetime.now() - dashboard_api.timedelta(days=3)
        ).isoformat()
        dashboard_api.save_profile(profile)

        response = client.post("/chat", json={"question": "How does Discere work?"})
        self.assertEqual(response.status_code, 402, response.text)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "subscription_required")
        self.assertTrue(detail["subscription"]["requires_subscription"])

        exempt_client = self.signup("bnzhang2001@gmail.com")
        exempt_user_id = "bnzhang2001_gmail_com"
        exempt_profile = dashboard_api.load_profile_or_404(exempt_user_id)
        exempt_profile["settings"]["SUBSCRIPTION_STATUS"] = "trialing"
        exempt_profile["settings"]["SUBSCRIPTION_TRIAL_STARTED_AT"] = (
            dashboard_api.datetime.now() - dashboard_api.timedelta(days=10)
        ).isoformat()
        exempt_profile["settings"]["SUBSCRIPTION_TRIAL_ENDS_AT"] = (
            dashboard_api.datetime.now() - dashboard_api.timedelta(days=3)
        ).isoformat()
        dashboard_api.save_profile(exempt_profile)

        exempt_status = exempt_client.get("/billing/status")
        self.assertEqual(exempt_status.status_code, 200, exempt_status.text)
        subscription = exempt_status.json()["subscription"]
        self.assertEqual(subscription["status"], "member")
        self.assertTrue(subscription["is_exempt"])
        self.assertFalse(subscription["requires_subscription"])

        exempt_checkout = exempt_client.post("/billing/checkout")
        self.assertEqual(exempt_checkout.status_code, 200, exempt_checkout.text)
        self.assertIn("No billing is required", exempt_checkout.json()["message"])

    def test_billing_checkout_is_stripe_ready_without_fake_success(self) -> None:
        client = self.signup("checkout@example.com")
        response = client.post("/billing/checkout")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertFalse(payload["checkout_configured"])
        self.assertFalse(payload["success"])
        self.assertIn("Stripe checkout", payload["message"])

    def test_scheduled_report_only_sends_summaries_from_current_run(self) -> None:
        client = self.signup("scheduled-run@example.com")
        self.connect_standard_mailbox(client, "scheduled-run@example.com")
        user_id = "scheduled_run_example_com"
        contact = "sender@example.com"
        contacts_response = client.post("/whitelist", json={"contacts": [contact]})
        self.assertEqual(contacts_response.status_code, 200, contacts_response.text)

        summaries_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        summaries_dir.mkdir(parents=True, exist_ok=True)
        old_summary = {
            "summary_id": "old_summary",
            "sender": contact,
            "title": "Old summary",
            "executive_summary": "This should not be emailed again.",
            "created_at": "2026-04-01T08:00:00",
        }
        new_summary = {
            "summary_id": "new_summary",
            "sender": contact,
            "title": "New summary",
            "executive_summary": "This was created by the scheduled run.",
            "created_at": "2026-04-28T08:00:00",
        }
        (summaries_dir / "old_summary.json").write_text(json.dumps(old_summary), encoding="utf-8")
        (summaries_dir / "new_summary.json").write_text(json.dumps(new_summary), encoding="utf-8")

        schedule_response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(schedule_response.status_code, 200, schedule_response.text)
        schedule_id = schedule_response.json()["schedule"]["schedule_id"]

        with patch.object(
            dashboard_api,
            "execute_summarizer_run",
            return_value={"success": True, "new_summary_ids": ["new_summary"]},
        ), patch.object(
            dashboard_api,
            "send_combined_report_via_smtp",
            return_value={"recipient": "scheduled-run@example.com"},
        ) as send_mock:
            dashboard_api.process_due_schedule(schedule_id)

        send_mock.assert_called_once()
        markdown = send_mock.call_args.args[2]
        self.assertIn("New summary", markdown)
        self.assertIn("This was created by the scheduled run.", markdown)
        self.assertNotIn("Old summary", markdown)
        self.assertNotIn("This should not be emailed again.", markdown)

    def test_scheduled_report_does_not_send_when_run_has_no_new_summaries(self) -> None:
        client = self.signup("scheduled-empty@example.com")
        self.connect_standard_mailbox(client, "scheduled-empty@example.com")
        contacts_response = client.post("/whitelist", json={"contacts": ["sender@example.com"]})
        self.assertEqual(contacts_response.status_code, 200, contacts_response.text)
        schedule_response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(schedule_response.status_code, 200, schedule_response.text)
        schedule_id = schedule_response.json()["schedule"]["schedule_id"]

        with patch.object(
            dashboard_api,
            "execute_summarizer_run",
            return_value={"success": True, "new_summary_ids": []},
        ), patch.object(dashboard_api, "send_combined_report_via_smtp") as send_mock:
            dashboard_api.process_due_schedule(schedule_id)

        send_mock.assert_not_called()

    def test_scheduled_report_with_no_contacts_skips_run_and_advances_schedule(self) -> None:
        client = self.signup("scheduled-no-contacts@example.com")
        self.connect_standard_mailbox(client, "scheduled-no-contacts@example.com")
        schedule_response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(schedule_response.status_code, 200, schedule_response.text)
        schedule_id = schedule_response.json()["schedule"]["schedule_id"]

        with patch.object(dashboard_api, "execute_summarizer_run") as run_mock, patch.object(
            dashboard_api, "send_combined_report_via_smtp"
        ) as send_mock:
            dashboard_api.process_due_schedule(schedule_id)

        run_mock.assert_not_called()
        send_mock.assert_not_called()
        schedules_response = client.get("/report-schedules")
        self.assertEqual(schedules_response.status_code, 200, schedules_response.text)
        schedule = schedules_response.json()["schedules"][0]
        self.assertTrue(schedule["last_run_at"])
        self.assertTrue(schedule["next_run_at"])

    def test_account_deletion_removes_account_scoped_database_rows_and_files(self) -> None:
        client = self.signup("delete@example.com")
        self.connect_standard_mailbox(client, "delete@example.com")
        user_id = "delete_example_com"
        client.post("/bug-reports", json={"user_id": user_id, "title": "Bug", "description": "Details"})
        client.post(
            "/report-schedules",
            json={
                "user_id": user_id,
                "name": "Daily",
                "recipient_email": "delete@example.com",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        user_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / user_id
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "marker.txt").write_text("private", encoding="utf-8")

        response = client.delete("/auth/account")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(user_dir.exists())

        with dashboard_api.get_db_connection() as connection:
            for table in ["users", "sessions", "report_schedules", "analytics_events", "bug_reports", "usage_counters"]:
                count = connection.execute(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE user_id = ?",
                    (user_id,),
                ).fetchone()["count"]
                self.assertEqual(count, 0, table)

    def test_readiness_endpoint_is_safe_and_configured(self) -> None:
        response = self.client.get("/health/readiness")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("checks", payload)
        self.assertTrue(payload["checks"]["security_headers_enabled"])
        self.assertTrue(payload["checks"]["cors_origins_production_safe"])
        serialized = json.dumps(payload)
        self.assertNotIn("test-openai-key", serialized)
        self.assertNotIn("test-only-encryption-key", serialized)

    def test_security_headers_are_applied(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers.get("content-security-policy", ""))
        self.assertIn("max-age=31536000", response.headers.get("strict-transport-security", ""))

    def test_rate_limit_blocks_repeated_login_attempts_when_enabled(self) -> None:
        original = os.environ.get("EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED", "")
        os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = "true"
        dashboard_api.RATE_LIMIT_BUCKETS.clear()
        try:
            for _ in range(20):
                response = self.client.post(
                    "/auth/login",
                    json={"email": "nobody@example.com", "password": "wrongpassword"},
                )
                self.assertEqual(response.status_code, 401, response.text)
            response = self.client.post(
                "/auth/login",
                json={"email": "nobody@example.com", "password": "wrongpassword"},
            )
            self.assertEqual(response.status_code, 429, response.text)
        finally:
            dashboard_api.RATE_LIMIT_BUCKETS.clear()
            os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = original

    def test_request_and_input_size_limits(self) -> None:
        client = self.signup("limits@example.com")

        response = client.post(
            "/bug-reports",
            json={"user_id": "limits_example_com", "title": "Bug", "description": "x" * (dashboard_api.MAX_BUG_DESCRIPTION_CHARS + 1)},
        )
        self.assertEqual(response.status_code, 413, response.text)

        response = client.post(
            "/summaries/combined",
            json={
                "user_id": "limits_example_com",
                "summary_ids": [f"summary-{index}" for index in range(dashboard_api.MAX_SUMMARY_IDS_PER_REQUEST + 1)],
            },
        )
        self.assertEqual(response.status_code, 413, response.text)

        original = os.environ.get("EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES", "")
        try:
            dashboard_api.MAX_REQUEST_BODY_BYTES = 10
            response = client.post(
                "/bug-reports",
                json={"user_id": "limits_example_com", "title": "Bug", "description": "Details"},
            )
            self.assertEqual(response.status_code, 413, response.text)
        finally:
            dashboard_api.MAX_REQUEST_BODY_BYTES = int(os.getenv("EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))
            if original:
                os.environ["EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES"] = original

    def test_admin_ui_is_not_user_accessible_and_endpoints_require_key(self) -> None:
        page_response = self.client.get("/admin")
        self.assertEqual(page_response.status_code, 404, page_response.text)

        static_page_response = self.client.get("/dashboard_static/admin.html")
        self.assertEqual(static_page_response.status_code, 404, static_page_response.text)

        blocked_response = self.client.get("/admin/analytics")
        self.assertEqual(blocked_response.status_code, 403, blocked_response.text)

        original_key = os.environ.get("EMAIL_SUMMARIZER_ADMIN_KEY", "")
        original_admin_emails = os.environ.get("EMAIL_SUMMARIZER_ADMIN_EMAILS", "")
        os.environ["EMAIL_SUMMARIZER_ADMIN_KEY"] = "test-admin-key"
        os.environ["EMAIL_SUMMARIZER_ADMIN_EMAILS"] = "admin@example.com"
        try:
            admin_client = self.signup("admin@example.com")
            email_based_response = admin_client.get("/admin/analytics")
            self.assertEqual(email_based_response.status_code, 403, email_based_response.text)

            allowed_response = self.client.get(
                "/admin/analytics",
                headers={"x-discere-admin-key": "test-admin-key"},
            )
            self.assertEqual(allowed_response.status_code, 200, allowed_response.text)
            self.assertIn("totals", allowed_response.json())

            monitoring_response = self.client.get(
                "/admin/monitoring",
                headers={"x-discere-admin-key": "test-admin-key"},
            )
            self.assertEqual(monitoring_response.status_code, 200, monitoring_response.text)
            self.assertIn("events", monitoring_response.json())
        finally:
            if original_key:
                os.environ["EMAIL_SUMMARIZER_ADMIN_KEY"] = original_key
            else:
                os.environ.pop("EMAIL_SUMMARIZER_ADMIN_KEY", None)
            if original_admin_emails:
                os.environ["EMAIL_SUMMARIZER_ADMIN_EMAILS"] = original_admin_emails
            else:
                os.environ.pop("EMAIL_SUMMARIZER_ADMIN_EMAILS", None)

    def test_daily_usage_limits_are_enforced_per_account(self) -> None:
        client = self.signup("usage@example.com")
        original_chat_limit = os.environ.get("EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY", "")
        os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = "1"
        try:
            first_response = client.post(
                "/chat",
                json={"user_id": "usage_example_com", "question": "What happened?"},
            )
            self.assertEqual(first_response.status_code, 404, first_response.text)

            usage_response = client.get("/usage")
            self.assertEqual(usage_response.status_code, 200, usage_response.text)
            chat_usage = usage_response.json()["usage"]["chat"]
            self.assertEqual(chat_usage["count"], 1)
            self.assertEqual(chat_usage["limit"], 1)

            second_response = client.post(
                "/chat",
                json={"user_id": "usage_example_com", "question": "What happened again?"},
            )
            self.assertEqual(second_response.status_code, 429, second_response.text)
        finally:
            os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = original_chat_limit or "100"

    def test_monitoring_records_security_events_without_sensitive_metadata(self) -> None:
        client = self.signup("monitor@example.com")
        response = client.get("/whitelist", params={"user_id": "other_user"})
        self.assertEqual(response.status_code, 403, response.text)

        dashboard_api.write_monitoring_event(
            "security",
            "manual_secret_test",
            "warning",
            user_id="monitor_example_com",
            metadata={"api_key": "should-redact", "safe": "visible"},
        )

        with dashboard_api.get_db_connection() as connection:
            rows = connection.execute(
                """
                SELECT category, event_name, severity, user_id, metadata_json
                FROM monitoring_events
                ORDER BY created_at DESC
                """
            ).fetchall()

        serialized = json.dumps([dict(row) for row in rows])
        self.assertIn("cross_account_user_id_override", serialized)
        self.assertIn("manual_secret_test", serialized)
        self.assertIn("[redacted]", serialized)
        self.assertNotIn("should-redact", serialized)


if __name__ == "__main__":
    unittest.main()
