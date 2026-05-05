import base64
import email
import json
import os
import shutil
import smtplib
import sys
import unittest
from pathlib import Path
from typing import List, Optional
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
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
os.environ["EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD"] = "test-private-invite"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import dashboard_api
import email_v13


def decoded_mime_text(raw_message: str) -> str:
    parsed = email.message_from_string(raw_message)
    parts = []
    for part in parsed.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        parts.append(payload.decode(charset, errors="replace"))
    return "\n".join(parts)


def make_unsigned_id_token(claims: dict) -> str:
    def encode(segment: dict) -> str:
        raw = json.dumps(segment, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    return f"{encode({'alg': 'none'})}.{encode(claims)}."


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"], ignore_errors=True)
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_OUTPUT_DIR"], ignore_errors=True)
        os.environ["EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD"] = "test-private-invite"
        os.environ.pop("EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS", None)
        os.environ.pop("EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL", None)
        os.environ.pop("EMAIL_SUMMARIZER_SMS_ENABLED", None)
        dashboard_api.initialize_database()
        self.client = TestClient(dashboard_api.app, base_url="https://discere-test.example")

    def signup(self, email: str) -> TestClient:
        client = TestClient(dashboard_api.app, base_url="https://discere-test.example")
        existing_allowlist = {
            item.strip().lower()
            for item in os.environ.get("EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS", "").split(",")
            if item.strip()
        }
        existing_allowlist.add(email.strip().lower())
        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = ",".join(sorted(existing_allowlist))
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = email.strip().lower()
        response = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "StrongPass123!",
                "manual_access_password": os.environ["EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD"],
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

    def test_home_remains_public_when_session_is_valid(self) -> None:
        client = self.signup("home-redirect@example.com")
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Discere", response.text)

    def test_home_stays_public_after_logout(self) -> None:
        client = self.signup("home-logout@example.com")
        logout_response = client.post("/auth/logout")
        self.assertEqual(logout_response.status_code, 200, logout_response.text)

        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)

    def test_login_redirects_valid_session_to_dashboard(self) -> None:
        client = self.signup("login-redirect@example.com")
        response = client.get("/login", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/dashboard")

    def test_public_signup_route_redirects_to_login(self) -> None:
        response = self.client.get("/signup", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/login")

        manual_response = self.client.get("/manual-signup")
        self.assertEqual(manual_response.status_code, 200, manual_response.text)
        self.assertIn("Private Client Signup", manual_response.text)

    def test_manual_signup_requires_allowlisted_email_and_private_password(self) -> None:
        blocked_response = self.client.post(
            "/auth/signup",
            json={
                "email": "public-blocked@example.com",
                "password": "StrongPass123!",
                "manual_access_password": "test-private-invite",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(blocked_response.status_code, 403, blocked_response.text)

        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "approved-private@example.com"
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "approved-private@example.com"
        wrong_password_response = self.client.post(
            "/auth/signup",
            json={
                "email": "approved-private@example.com",
                "password": "StrongPass123!",
                "manual_access_password": "wrong",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(wrong_password_response.status_code, 403, wrong_password_response.text)

        allowed_response = self.client.post(
            "/auth/signup",
            json={
                "email": "approved-private@example.com",
                "password": "StrongPass123!",
                "manual_access_password": "test-private-invite",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(allowed_response.status_code, 200, allowed_response.text)
        self.assertTrue(allowed_response.json()["profile"]["manual_mailbox_allowed"])

    def test_manual_signup_requires_explicit_configured_private_password(self) -> None:
        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "approved-private@example.com"
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "approved-private@example.com"
        os.environ.pop("EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD", None)

        response = self.client.post(
            "/auth/signup",
            json={
                "email": "approved-private@example.com",
                "password": "StrongPass123!",
                "manual_access_password": "VIPCLIENT",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn("VIPCLIENT", response.text)

    def test_manual_signup_only_preconfigures_configured_vip_email(self) -> None:
        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "vip-client@263.com,other-client@example.com"
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "vip-client@263.com"

        blocked_response = self.client.post(
            "/auth/signup",
            json={
                "email": "other-client@example.com",
                "password": "StrongPass123!",
                "manual_access_password": "test-private-invite",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(blocked_response.status_code, 403, blocked_response.text)

        allowed_response = self.client.post(
            "/auth/signup",
            json={
                "email": "vip-client@263.com",
                "password": "ClientChosenPass123!",
                "manual_access_password": "test-private-invite",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(allowed_response.status_code, 200, allowed_response.text)
        profile_payload = allowed_response.json()["profile"]
        settings = profile_payload["settings"]
        self.assertFalse(settings["mailbox_connected"])
        self.assertEqual(settings["imap_user"], "vip-client@263.com")
        self.assertEqual(settings["imap_server"], "imap.263.net")
        self.assertEqual(settings["imap_port"], "993")

        profile = dashboard_api.load_profile_or_404("vip_client_263_com")
        stored_settings = profile["settings"]
        self.assertEqual(stored_settings["SMTP_HOST"], "smtp.263.net")
        self.assertEqual(stored_settings["SMTP_PORT"], "465")
        self.assertEqual(stored_settings["IMAP_PASSWORD"], "")

    def test_vip_saves_own_mailbox_password_after_signup(self) -> None:
        client = self.signup("vip-own-password@263.com")

        with patch("dashboard_api.imaplib.IMAP4_SSL") as mock_imap:
            mock_mail = MagicMock()
            mock_imap.return_value = mock_mail
            response = client.post(
                "/mailbox/vip-password",
                json={"mailbox_password": "vip-user-entered-app-password"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        mock_imap.assert_called_once_with("imap.263.net", 993)
        mock_mail.login.assert_called_once_with("vip-own-password@263.com", "vip-user-entered-app-password")
        mock_mail.logout.assert_called_once()
        profile_payload = response.json()["profile"]
        self.assertTrue(profile_payload["settings"]["mailbox_connected"])
        serialized_profile = json.dumps(profile_payload)
        self.assertNotIn("vip-user-entered-app-password", serialized_profile)
        self.assertNotIn("mailbox_password", serialized_profile.lower())
        self.assertNotIn("imap_password", serialized_profile.lower())
        self.assertNotIn("smtp_password", serialized_profile.lower())

        profile = dashboard_api.load_profile_or_404("vip_own_password_263_com")
        self.assertEqual(profile["settings"]["IMAP_PASSWORD"], "vip-user-entered-app-password")
        self.assertEqual(profile["settings"]["SMTP_PASSWORD"], "vip-user-entered-app-password")
        self.assertEqual(profile["settings"]["MAILBOX_CONNECTION_CONFIRMED"], "true")

        with dashboard_api.get_db_connection() as connection:
            row = connection.execute(
                "SELECT settings_json FROM users WHERE user_id = ?",
                ("vip_own_password_263_com",),
            ).fetchone()
        self.assertTrue(str(row["settings_json"]).startswith("enc::"))
        self.assertNotIn("vip-user-entered-app-password", row["settings_json"])

    def test_vip_mailbox_password_endpoint_rejects_bad_password_without_saving(self) -> None:
        client = self.signup("vip-bad-password@263.com")

        with patch("dashboard_api.imaplib.IMAP4_SSL") as mock_imap:
            mock_mail = MagicMock()
            mock_mail.login.side_effect = Exception("bad credentials")
            mock_imap.return_value = mock_mail
            response = client.post(
                "/mailbox/vip-password",
                json={"mailbox_password": "wrong-password"},
            )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Incorrect 263 mail password", response.text)
        profile = dashboard_api.load_profile_or_404("vip_bad_password_263_com")
        self.assertEqual(profile["settings"]["IMAP_PASSWORD"], "")
        self.assertEqual(profile["settings"]["MAILBOX_CONNECTION_CONFIRMED"], "false")

    def test_vip_mailbox_password_endpoint_rejects_non_vip_accounts(self) -> None:
        client = self.signup("approved-vip@263.com")
        profile = dashboard_api.load_profile_or_404("approved_vip_263_com")
        profile["google_oauth"] = {"email": "approved-vip@263.com", "access_token": "token"}
        dashboard_api.save_profile(profile)

        response = client.post(
            "/mailbox/vip-password",
            json={"mailbox_password": "should-not-save"},
        )
        self.assertEqual(response.status_code, 403, response.text)
        refreshed = dashboard_api.load_profile_or_404("approved_vip_263_com")
        self.assertNotIn("should-not-save", json.dumps(refreshed.get("settings", {})))

    def test_vip_signup_without_mailbox_password_does_not_crash(self) -> None:
        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "vip-missing@263.com"
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "vip-missing@263.com"

        response = self.client.post(
            "/auth/signup",
            json={
                "email": "vip-missing@263.com",
                "password": "StrongPass123!",
                "manual_access_password": "test-private-invite",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["profile"]["settings"]["mailbox_connected"])
        profile = dashboard_api.load_profile_or_404("vip_missing_263_com")
        self.assertEqual(profile["settings"]["IMAP_SERVER"], "imap.263.net")
        self.assertEqual(profile["settings"]["IMAP_PASSWORD"], "")

    def test_oauth_accounts_do_not_receive_vip_263_defaults(self) -> None:
        os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "vip-client@263.com"
        os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "vip-client@263.com"
        settings = dashboard_api.apply_provider_defaults(dashboard_api.default_profile_settings(), "google-user@gmail.com")
        self.assertNotEqual(settings.get("IMAP_SERVER"), "imap.263.net")
        self.assertEqual(settings.get("IMAP_SERVER"), "imap.gmail.com")

        default_settings = dashboard_api.apply_provider_defaults(dashboard_api.default_profile_settings(), "public@example.com")
        self.assertNotEqual(default_settings.get("IMAP_SERVER"), "imap.263.net")

    def test_non_allowlisted_user_cannot_save_manual_mailbox_password(self) -> None:
        original_allowlist = os.environ.get("EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS", "")
        original_vip = os.environ.get("EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL", "")
        try:
            os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = "temporary-standard@example.com"
            os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = "temporary-standard@example.com"
            client = TestClient(dashboard_api.app, base_url="https://discere-test.example")
            signup_response = client.post(
                "/auth/signup",
                json={
                    "email": "temporary-standard@example.com",
                    "password": "StrongPass123!",
                    "manual_access_password": "test-private-invite",
                    "accept_terms": True,
                    "accept_privacy": True,
                },
            )
            self.assertEqual(signup_response.status_code, 200, signup_response.text)
            os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = ""

            response = client.put(
                "/profile",
                json={
                    "email": "temporary-standard@example.com",
                    "imap_user": "temporary-standard@example.com",
                    "imap_password": "MailboxPass123!",
                },
            )
            self.assertEqual(response.status_code, 403, response.text)
        finally:
            os.environ["EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS"] = original_allowlist
            os.environ["EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL"] = original_vip

    def test_login_and_mailbox_passwords_are_encrypted_and_not_returned(self) -> None:
        client = self.signup("password-storage@example.com")
        self.connect_standard_mailbox(client, "password-storage@example.com")

        profile_response = client.get("/auth/me")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        serialized_profile = json.dumps(profile_response.json())
        self.assertNotIn("StrongPass123!", serialized_profile)
        self.assertNotIn("MailboxPass123!", serialized_profile)
        self.assertNotIn("password_hash", serialized_profile)
        self.assertNotIn("password_salt", serialized_profile)
        self.assertNotIn("imap_password", serialized_profile.lower())
        self.assertNotIn("smtp_password", serialized_profile.lower())

        with dashboard_api.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT password_hash, password_salt, settings_json
                FROM users
                WHERE user_id = ?
                """,
                ("password_storage_example_com",),
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], "StrongPass123!")
        self.assertTrue(row["password_salt"])
        self.assertTrue(str(row["settings_json"]).startswith("enc::"))
        self.assertNotIn("MailboxPass123!", row["settings_json"])
        self.assertNotIn("password-storage@example.com", row["settings_json"])

    def test_oauth_tokens_are_encrypted_and_not_returned(self) -> None:
        client = self.signup("oauth-secret-storage@example.com")
        profile = dashboard_api.load_profile_or_404("oauth_secret_storage_example_com")
        profile["google_oauth"] = {
            "provider": "google",
            "email": "oauth-secret-storage@example.com",
            "access_token": "google-access-secret",
            "refresh_token": "google-refresh-secret",
            "id_token": "google-id-secret",
        }
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "oauth-secret-storage@example.com",
            "access_token": "microsoft-access-secret",
            "refresh_token": "microsoft-refresh-secret",
            "id_token": "microsoft-id-secret",
        }
        dashboard_api.save_profile(profile)

        profile_response = client.get("/auth/me")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        serialized_profile = json.dumps(profile_response.json())
        for secret in [
            "google-access-secret",
            "google-refresh-secret",
            "google-id-secret",
            "microsoft-access-secret",
            "microsoft-refresh-secret",
            "microsoft-id-secret",
        ]:
            self.assertNotIn(secret, serialized_profile)

        with dashboard_api.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT google_oauth_json, microsoft_oauth_json
                FROM users
                WHERE user_id = ?
                """,
                ("oauth_secret_storage_example_com",),
            ).fetchone()

        self.assertTrue(str(row["google_oauth_json"]).startswith("enc::"))
        self.assertTrue(str(row["microsoft_oauth_json"]).startswith("enc::"))
        self.assertNotIn("google-refresh-secret", row["google_oauth_json"])
        self.assertNotIn("microsoft-refresh-secret", row["microsoft_oauth_json"])

    def test_email_hint_flags_default_false_and_persist_true(self) -> None:
        client = self.signup("email-hints@example.com")
        profile_response = client.get("/profile")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        settings = profile_response.json()["profile"]["settings"]
        self.assertFalse(settings["has_seen_profile_name_prompt"])
        self.assertFalse(settings["has_seen_combined_summary_email_hint"])
        self.assertFalse(settings["has_seen_single_summary_email_hint"])

        mark_response = client.post(
            "/profile/ui-hint-seen",
            json={"hint_key": "has_seen_profile_name_prompt"},
        )
        self.assertEqual(mark_response.status_code, 200, mark_response.text)
        updated_settings = mark_response.json()["profile"]["settings"]
        self.assertTrue(updated_settings["has_seen_profile_name_prompt"])
        self.assertFalse(updated_settings["has_seen_combined_summary_email_hint"])

        mark_response = client.post(
            "/profile/ui-hint-seen",
            json={"hint_key": "has_seen_combined_summary_email_hint"},
        )
        self.assertEqual(mark_response.status_code, 200, mark_response.text)
        updated_settings = mark_response.json()["profile"]["settings"]
        self.assertTrue(updated_settings["has_seen_combined_summary_email_hint"])
        self.assertFalse(updated_settings["has_seen_single_summary_email_hint"])

        persisted_response = client.get("/profile")
        self.assertEqual(persisted_response.status_code, 200, persisted_response.text)
        persisted_settings = persisted_response.json()["profile"]["settings"]
        self.assertTrue(persisted_settings["has_seen_profile_name_prompt"])
        self.assertTrue(persisted_settings["has_seen_combined_summary_email_hint"])

    def test_unknown_email_hint_key_is_rejected(self) -> None:
        client = self.signup("bad-email-hint@example.com")
        response = client.post(
            "/profile/ui-hint-seen",
            json={"hint_key": "not_a_real_hint"},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Unknown UI hint", response.json()["detail"])

    def test_login_redirects_valid_session_to_safe_next_destination(self) -> None:
        client = self.signup("login-next@example.com")
        response = client.get("/login?next=/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/dashboard")

    def test_login_rejects_external_next_redirects(self) -> None:
        client = self.signup("login-safe-next@example.com")
        response = client.get("/login?next=https://evil.example/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/dashboard")

    def test_dashboard_requires_session_and_preserves_next_destination(self) -> None:
        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/login?next=%2Fdashboard")

    def test_dashboard_serves_logged_in_session(self) -> None:
        client = self.signup("dashboard-auth@example.com")
        response = client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Email Dashboard", response.text)

    def test_report_email_dashboard_link_points_to_dashboard(self) -> None:
        self.assertEqual(dashboard_api.dashboard_url(), "https://discere-test.example/dashboard")

    def test_session_cookie_uses_seven_day_default_and_refreshes(self) -> None:
        client = self.signup("remember-session@example.com")
        response = client.get("/auth/me")
        self.assertEqual(response.status_code, 200, response.text)
        set_cookie = response.headers.get("set-cookie", "")
        self.assertIn(dashboard_api.SESSION_COOKIE_NAME, set_cookie)
        self.assertIn(f"Max-Age={dashboard_api.SESSION_COOKIE_MAX_AGE_SECONDS}", set_cookie)
        self.assertEqual(dashboard_api.SESSION_COOKIE_MAX_AGE_SECONDS, 60 * 60 * 24 * 7)

    def test_manual_account_keeps_legal_and_how_to_flags_after_later_login(self) -> None:
        client = self.signup("manual-lifecycle@example.com")
        user_id = "manual_lifecycle_example_com"

        response = client.post(f"/profile/how-to-seen?user_id={user_id}")
        self.assertEqual(response.status_code, 200, response.text)
        profile = response.json()["profile"]
        self.assertTrue(profile["settings"]["terms_accepted"])
        self.assertTrue(profile["settings"]["privacy_accepted"])
        self.assertTrue(profile["settings"]["how_to_seen"])

        logout_response = client.post("/auth/logout")
        self.assertEqual(logout_response.status_code, 200, logout_response.text)
        login_response = client.post(
            "/auth/login",
            json={"email": "manual-lifecycle@example.com", "password": "StrongPass123!"},
        )
        self.assertEqual(login_response.status_code, 200, login_response.text)
        login_profile = login_response.json()["profile"]
        self.assertTrue(login_profile["settings"]["terms_accepted"])
        self.assertTrue(login_profile["settings"]["privacy_accepted"])
        self.assertTrue(login_profile["settings"]["how_to_seen"])

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
            self.assertNotIn("include_granted_scopes", query)
            scopes = query.get("scope", [""])[0].split()
            self.assertEqual(scopes, [dashboard_api.REQUIRED_GOOGLE_READ_SCOPE])
            self.assertIn(dashboard_api.REQUIRED_GOOGLE_READ_SCOPE, scopes)
            self.assertNotIn("openid", scopes)
            self.assertNotIn("email", scopes)
            self.assertNotIn("profile", scopes)
            self.assertNotIn("https://www.googleapis.com/auth/gmail.send", scopes)
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_google_oauth_account_keeps_legal_and_how_to_flags_after_relogin(self) -> None:
        originals = {
            "GOOGLE_CLIENT_ID": os.environ.get("GOOGLE_CLIENT_ID"),
            "GOOGLE_CLIENT_SECRET": os.environ.get("GOOGLE_CLIENT_SECRET"),
            "GOOGLE_REDIRECT_URI": os.environ.get("GOOGLE_REDIRECT_URI"),
        }
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-client"
        os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-secret"
        os.environ["GOOGLE_REDIRECT_URI"] = "https://discere-test.example/auth/google/callback"
        try:
            for suffix in ("first", "second"):
                start_response = self.client.get("/auth/google/start", follow_redirects=False)
                self.assertEqual(start_response.status_code, 307, start_response.text)
                state = parse_qs(urlparse(start_response.headers["location"]).query)["state"][0]
                token_payload = {
                    "access_token": f"google-access-{suffix}",
                    "refresh_token": f"google-refresh-{suffix}",
                    "scope": dashboard_api.REQUIRED_GOOGLE_READ_SCOPE,
                    "id_token": "google-id-token",
                }
                userinfo = {"email": "oauth-lifecycle@gmail.com", "name": "OAuth Lifecycle"}
                with patch.object(dashboard_api, "post_form_json", return_value=token_payload), patch.object(
                    dashboard_api,
                    "get_json_with_bearer",
                    return_value=userinfo,
                ):
                    callback_response = self.client.get(
                        f"/auth/google/callback?code=test-code-{suffix}&state={state}",
                        follow_redirects=False,
                    )
                self.assertEqual(callback_response.status_code, 307, callback_response.text)

                if suffix == "first":
                    legal_response = self.client.post(
                        "/profile/legal-acceptance",
                        json={"accept_terms": True, "accept_privacy": True},
                    )
                    self.assertEqual(legal_response.status_code, 200, legal_response.text)
                    how_to_response = self.client.post("/profile/how-to-seen")
                    self.assertEqual(how_to_response.status_code, 200, how_to_response.text)

            profile = dashboard_api.profile_response(dashboard_api.load_profile_or_404("oauth_lifecycle_gmail_com"))
            self.assertTrue(profile["settings"]["terms_accepted"])
            self.assertTrue(profile["settings"]["privacy_accepted"])
            self.assertTrue(profile["settings"]["how_to_seen"])
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_oauth_start_requests_graph_mail_scope_without_graph_user_read(self) -> None:
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
            self.assertIn(dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE, scopes)
            self.assertNotIn("User.Read", scopes)
            self.assertEqual(query.get("prompt"), ["consent"])
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_oauth_account_keeps_legal_and_how_to_flags_after_relogin(self) -> None:
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
            for suffix in ("first", "second"):
                start_response = self.client.get("/auth/microsoft/start", follow_redirects=False)
                self.assertEqual(start_response.status_code, 307, start_response.text)
                state = parse_qs(urlparse(start_response.headers["location"]).query)["state"][0]
                id_token = make_unsigned_id_token(
                    {
                        "preferred_username": "oauth-lifecycle@outlook.com",
                        "email": "oauth-lifecycle@outlook.com",
                        "name": "OAuth Lifecycle",
                    }
                )
                token_payload = {
                    "access_token": f"microsoft-access-{suffix}",
                    "refresh_token": f"microsoft-refresh-{suffix}",
                    "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
                    "id_token": id_token,
                }
                with patch.object(dashboard_api, "post_form_json", return_value=token_payload):
                    callback_response = self.client.get(
                        f"/auth/microsoft/callback?code=test-code-{suffix}&state={state}",
                        follow_redirects=False,
                    )
                self.assertEqual(callback_response.status_code, 307, callback_response.text)

                if suffix == "first":
                    legal_response = self.client.post(
                        "/profile/legal-acceptance",
                        json={"accept_terms": True, "accept_privacy": True},
                    )
                    self.assertEqual(legal_response.status_code, 200, legal_response.text)
                    how_to_response = self.client.post("/profile/how-to-seen")
                    self.assertEqual(how_to_response.status_code, 200, how_to_response.text)

            profile = dashboard_api.profile_response(dashboard_api.load_profile_or_404("oauth_lifecycle_outlook_com"))
            self.assertTrue(profile["settings"]["terms_accepted"])
            self.assertTrue(profile["settings"]["privacy_accepted"])
            self.assertTrue(profile["settings"]["how_to_seen"])
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
                "access_token": "outlook-graph-access-token",
                "refresh_token": "outlook-refresh-token",
                "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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
            self.assertEqual(profile["microsoft_oauth"]["access_token"], "outlook-graph-access-token")
            self.assertTrue(dashboard_api.microsoft_oauth_has_scope(profile, dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE))
            profile_payload = dashboard_api.profile_response(profile)
            self.assertEqual(profile_payload["settings"]["first_name"], "")
            self.assertEqual(profile_payload["settings"]["last_name"], "")
            self.assertFalse(profile_payload["settings"]["has_seen_profile_name_prompt"])
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
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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

    def test_microsoft_refresh_missing_mail_scope_returns_clean_reconnect_error(self) -> None:
        client = self.signup("missing-scope-outlook@example.com")
        user_id = "missing_scope_outlook_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "missing-scope-outlook@example.com",
            "access_token": "expired-access-token",
            "refresh_token": "stored-refresh-token",
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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
                return_value={"access_token": "fresh-access-token", "refresh_token": "rotated-refresh-token", "scope": "offline_access"},
            ):
                response = client.post("/run-summarizer", json={"days_back": 7})

            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn("Microsoft mailbox access needs approval", response.json()["detail"])
            self.assertEqual(response.headers.get("X-Discere-Reconnect-Provider"), "microsoft")
            self.assertIn("force_reconsent=true", response.headers.get("X-Discere-Reconnect-Url", ""))
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_graph_401_from_subprocess_returns_clean_reconnect_job(self) -> None:
        self.signup("graph-401@example.com")
        user_id = "graph_401_example_com"
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "graph-401@example.com",
            "access_token": "expired-access-token",
            "refresh_token": "stored-refresh-token",
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
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
        fake_result = SimpleNamespace(
            returncode=1,
            stdout='{"success": false, "error": "Microsoft mailbox access expired or needs permission again. Please reconnect Microsoft in Settings, then try again."}\n',
            stderr="Traceback (most recent call last):\nValueError: Microsoft Graph request failed for messages: HTTP Error 401: Unauthorized",
        )
        try:
            with patch.object(
                dashboard_api,
                "post_form_json",
                return_value={"access_token": "fresh-access-token", "refresh_token": "rotated-refresh-token", "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE},
            ), patch.object(dashboard_api.subprocess, "run", return_value=fake_result):
                result = dashboard_api.execute_summarizer_run(user_id, 7)

            self.assertFalse(result["success"])
            self.assertEqual(result["message"], dashboard_api.MICROSOFT_RECONNECT_MESSAGE)
            self.assertEqual(result["stderr"], dashboard_api.MICROSOFT_RECONNECT_MESSAGE)
            self.assertNotIn("Traceback", result["stderr"])
            self.assertEqual(result["reconnect_provider"], "microsoft")
            self.assertIn("/auth/microsoft/start?", result["reconnect_url"])
            self.assertIn("force_reconsent=true", result["reconnect_url"])
        finally:
            for key, value in originals.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_microsoft_graph_search_filters_to_tracked_senders_locally(self) -> None:
        summarizer = object.__new__(email_v13.EmailSummarizer)
        summarizer.whitelist = ["tracked@example.com"]
        summarizer.whitelist_set = {"tracked@example.com"}
        summarizer._uid_token = email_v13.EmailSummarizer._uid_token
        summarizer._microsoft_numeric_uid = staticmethod(email_v13.EmailSummarizer._microsoft_numeric_uid)
        summarizer._message_sender = email_v13.EmailSummarizer._message_sender.__get__(summarizer, email_v13.EmailSummarizer)
        summarizer._is_tracked_sender = email_v13.EmailSummarizer._is_tracked_sender.__get__(summarizer, email_v13.EmailSummarizer)

        raw_messages = {
            "tracked-id": "From: Tracked Person <tracked@example.com>\nSubject: Important\n\nTracked body",
            "blank-id": "From: Tracked Person <tracked@example.com>\nSubject: Blank metadata\n\nTracked body",
        }
        fetched_paths: List[str] = []

        def fake_graph_request(path_or_url: str, params: Optional[dict] = None, raw: bool = False):
            if raw:
                raise AssertionError("Raw Microsoft Graph fetches should go through _microsoft_graph_raw_message.")
            self.assertEqual(path_or_url, "messages")
            self.assertNotIn("$filter", params or {})
            return {
                "value": [
                    {
                        "id": "tracked-id",
                        "conversationId": "conversation-tracked",
                        "receivedDateTime": "2026-05-05T15:00:00Z",
                        "from": {"emailAddress": {"address": "tracked@example.com"}},
                    },
                    {
                        "id": "untracked-id",
                        "conversationId": "conversation-untracked",
                        "receivedDateTime": "2026-05-05T15:00:00Z",
                        "from": {"emailAddress": {"address": "untracked@example.com"}},
                    },
                    {
                        "id": "blank-id",
                        "conversationId": "conversation-blank",
                        "receivedDateTime": "2026-05-05T14:00:00Z",
                        "from": {"emailAddress": {"address": ""}},
                    },
                    {
                        "id": "old-id",
                        "conversationId": "conversation-old",
                        "receivedDateTime": "2026-04-01T14:00:00Z",
                        "from": {"emailAddress": {"address": "tracked@example.com"}},
                    },
                ]
            }

        def fake_raw_message(graph_message_id: str, conversation_id: str = ""):
            fetched_paths.append(graph_message_id)
            message = email.message_from_string(raw_messages[graph_message_id])
            message.microsoft_message_id = graph_message_id
            message.microsoft_conversation_id = conversation_id
            return message

        summarizer._microsoft_graph_request = fake_graph_request
        summarizer._microsoft_graph_raw_message = fake_raw_message

        messages, stats = summarizer.fetch_trigger_emails_microsoft_graph(days_back=7, processed_uids=set())

        self.assertEqual([message.get("Subject") for message in messages], ["Important", "Blank metadata"])
        self.assertEqual(fetched_paths, ["tracked-id", "blank-id"])
        self.assertEqual(stats["candidate_trigger_count"], 2)
        self.assertEqual(stats["untracked_sender_count"], 0)

    def test_microsoft_saved_summary_uses_standard_dashboard_lifecycle(self) -> None:
        client = self.signup("microsoft-summary@example.com")
        user_id = "microsoft_summary_example_com"
        contact = "tracked@example.com"
        whitelist_response = client.post("/whitelist", json={"contacts": [contact]})
        self.assertEqual(whitelist_response.status_code, 200, whitelist_response.text)
        profile = dashboard_api.load_profile_or_404(user_id)
        profile["microsoft_oauth"] = {
            "provider": "microsoft",
            "email": "microsoft-summary@example.com",
            "access_token": "microsoft-access",
            "refresh_token": "microsoft-refresh",
            "scope": dashboard_api.REQUIRED_MICROSOFT_MAIL_SCOPE,
        }
        dashboard_api.save_profile(profile)

        summaries_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        emails_dir = dashboard_api.get_user_json_emails_dir(user_id)
        summaries_dir.mkdir(parents=True, exist_ok=True)
        emails_dir.mkdir(parents=True, exist_ok=True)
        summary_payload = {
            "summary_id": "microsoft_summary",
            "user_id": user_id,
            "sender": contact,
            "title": "Microsoft summary",
            "executive_summary": "Microsoft summary card should appear.",
            "summary_markdown": "# Email Summary\n\n## Executive Summary\nMicrosoft summary card should appear.",
            "source_uids": ["12345"],
            "source_email_file_ids": ["microsoft-email-one"],
            "created_at": "2026-05-05T15:00:00",
            "updated_at": "2026-05-05T15:00:00",
        }
        email_payload = {
            "email_id": "microsoft-email-one",
            "uid": "12345",
            "sender": contact,
            "subject": "Microsoft thread",
            "date": "2026-05-05T15:00:00",
            "thread": [
                {
                    "message_id": "microsoft-message-one",
                    "date": "2026-05-05T15:00:00",
                    "sender": contact,
                    "to": "microsoft-summary@example.com",
                    "subject": "Microsoft thread",
                    "body": "Saved Microsoft thread body.",
                }
            ],
        }
        (summaries_dir / "microsoft_summary.json").write_text(json.dumps(summary_payload), encoding="utf-8")
        (emails_dir / "microsoft-email-one.json").write_text(json.dumps(email_payload), encoding="utf-8")
        dashboard_api.save_processed_uids_for_user(user_id, ["12345"])

        list_response = client.get("/summaries")
        self.assertEqual(list_response.status_code, 200, list_response.text)
        self.assertIn("microsoft_summary", {item["summary_id"] for item in list_response.json()["summaries"]})

        detail_response = client.get("/summaries/microsoft_summary")
        self.assertEqual(detail_response.status_code, 200, detail_response.text)
        self.assertIn("Microsoft summary card should appear.", detail_response.text)

        thread_response = client.get("/summaries/microsoft_summary/thread")
        self.assertEqual(thread_response.status_code, 200, thread_response.text)
        self.assertTrue(thread_response.json()["content_available"])
        self.assertEqual(thread_response.json()["threads"][0]["thread"][0]["body"], "Saved Microsoft thread body.")

        read_response = client.post("/summaries/microsoft_summary/mark-read")
        self.assertEqual(read_response.status_code, 200, read_response.text)
        self.assertTrue(read_response.json()["read_at"])

        done_response = client.post("/summaries/microsoft_summary/mark-done", json={"done": True})
        self.assertEqual(done_response.status_code, 200, done_response.text)
        self.assertTrue(done_response.json()["done_at"])

        delete_response = client.delete("/summaries/microsoft_summary")
        self.assertEqual(delete_response.status_code, 200, delete_response.text)
        self.assertIn("12345", delete_response.json()["removed_uids"])
        self.assertNotIn("12345", dashboard_api.load_processed_uids_for_user(user_id))

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

    def test_new_accounts_default_to_default_background_theme(self) -> None:
        client = self.signup("theme-default@example.com")
        profile_response = client.get("/auth/me")
        self.assertEqual(profile_response.status_code, 200, profile_response.text)
        self.assertEqual(profile_response.json()["profile"]["settings"]["background_theme"], "default")

    def test_background_theme_is_account_scoped_setting(self) -> None:
        client = self.signup("theme-owner@example.com")
        update_response = client.put(
            "/profile",
            json={"email": "theme-owner@example.com", "background_theme": "green"},
        )
        self.assertEqual(update_response.status_code, 200, update_response.text)
        self.assertEqual(update_response.json()["profile"]["settings"]["background_theme"], "green")

        other_client = self.signup("theme-other@example.com")
        other_profile_response = other_client.get("/auth/me")
        self.assertEqual(other_profile_response.status_code, 200, other_profile_response.text)
        self.assertEqual(other_profile_response.json()["profile"]["settings"]["background_theme"], "default")

    def test_summary_thread_endpoint_uses_saved_local_data_only(self) -> None:
        client = self.signup("thread-local@example.com")
        user_id = "thread_local_example_com"
        summary_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        emails_dir = dashboard_api.get_user_json_emails_dir(user_id)
        summary_dir.mkdir(parents=True, exist_ok=True)
        emails_dir.mkdir(parents=True, exist_ok=True)
        (summary_dir / "saved-thread.json").write_text(
            json.dumps(
                {
                    "summary_id": "saved-thread",
                    "title": "Saved Thread",
                    "source_email_file_ids": ["email-one"],
                }
            ),
            encoding="utf-8",
        )
        (emails_dir / "email-one.json").write_text(
            json.dumps(
                {
                    "email_id": "email-one",
                    "subject": "Local Only",
                    "sender": "sender@example.com",
                    "date": "2026-04-29T12:00:00",
                    "thread": [
                        {
                            "message_id": "m1",
                            "date": "2026-04-29T12:00:00",
                            "sender": "sender@example.com",
                            "to": "thread-local@example.com",
                            "subject": "Local Only",
                            "body": "Saved body",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        with patch.object(
            dashboard_api,
            "purge_old_read_source_data",
            side_effect=AssertionError("Full thread view should not run retention purge."),
        ):
            response = client.get("/summaries/saved-thread/thread")

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["content_available"])
        self.assertEqual(payload["threads"][0]["thread"][0]["body"], "Saved body")

    def test_summary_thread_endpoint_reports_purged_local_data(self) -> None:
        client = self.signup("thread-purged@example.com")
        user_id = "thread_purged_example_com"
        summary_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        emails_dir = dashboard_api.get_user_json_emails_dir(user_id)
        summary_dir.mkdir(parents=True, exist_ok=True)
        emails_dir.mkdir(parents=True, exist_ok=True)
        (summary_dir / "purged-thread.json").write_text(
            json.dumps(
                {
                    "summary_id": "purged-thread",
                    "title": "Purged Thread",
                    "source_email_file_ids": ["email-purged"],
                }
            ),
            encoding="utf-8",
        )
        (emails_dir / "email-purged.json").write_text(
            json.dumps(
                {
                    "email_id": "email-purged",
                    "content_purged_at": "2026-04-29T12:00:00",
                    "thread": [{"body": ""}],
                }
            ),
            encoding="utf-8",
        )

        response = client.get("/summaries/purged-thread/thread")

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertFalse(payload["content_available"])
        self.assertEqual(payload["purged_email_count"], 1)
        self.assertIn("no longer stored", payload["unavailable_reason"])

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
        self.assertIn("Mailbox connection is not ready", response.json()["detail"])

        result = dashboard_api.execute_summarizer_run("needs_mailbox_example_com", 7)
        self.assertFalse(result["success"])
        self.assertIn("Mailbox connection is not ready", result["stderr"])

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
        self.assertIn("Mailbox connection is not ready", response.json()["detail"])

    def test_summarizer_job_failure_does_not_expose_raw_traceback(self) -> None:
        client = self.signup("raw-error@example.com")
        self.connect_standard_mailbox(client, "raw-error@example.com")
        fake_result = SimpleNamespace(
            returncode=1,
            stdout="2026-05-01 INFO Loaded config\n",
            stderr="Traceback (most recent call last):\nValueError: database secret token raw failure",
        )

        with patch.object(dashboard_api.subprocess, "run", return_value=fake_result):
            result = dashboard_api.execute_summarizer_run("raw_error_example_com", 7)

        self.assertFalse(result["success"])
        self.assertEqual(result["stdout"], "")
        self.assertNotIn("Traceback", result["stderr"])
        self.assertNotIn("database secret", result["stderr"])
        self.assertIn("Discere could not finish", result["stderr"])

    def test_sms_endpoint_is_disabled_by_default(self) -> None:
        client = self.signup("sms-disabled@example.com")
        response = client.post(
            "/summaries/combined/send-text",
            json={"summary_ids": ["anything"], "phone_number": "+14155550123"},
        )

        self.assertEqual(response.status_code, 404, response.text)
        self.assertIn("SMS delivery is not available", response.json()["detail"])

    def test_settings_summary_preferences_are_escaped_in_frontend(self) -> None:
        settings_html = (Path(__file__).resolve().parents[1] / "dashboard_static" / "settings.html").read_text(encoding="utf-8")
        self.assertIn("function escapeHtml", settings_html)
        self.assertIn("escapeHtml(preference)", settings_html)

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

    def test_adding_tracked_contact_does_not_notify_contact(self) -> None:
        client = self.signup("contact-owner@example.com")
        with patch.object(dashboard_api, "send_report_email_from_discere") as send_mock:
            response = client.post("/whitelist", json={"contacts": ["tracked-contact@example.com"]})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["contacts"], ["tracked-contact@example.com"])
        send_mock.assert_not_called()

    def test_manual_single_summary_report_goes_to_user_not_tracked_contact(self) -> None:
        client = self.signup("single-report-owner@example.com")
        self.connect_standard_mailbox(client, "single-report-owner@example.com")
        contact_response = client.post("/whitelist", json={"contacts": ["tracked-contact@example.com"]})
        self.assertEqual(contact_response.status_code, 200, contact_response.text)

        summary = {
            "summary_id": "tracked_contact_summary",
            "sender": "tracked-contact@example.com",
            "title": "Tracked contact summary",
            "executive_summary": "Important update from the tracked contact.",
        }
        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "single-report-owner@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_summary_via_smtp("single_report_owner_example_com", summary)

        send_mock.assert_called_once()
        self.assertEqual(send_mock.call_args.kwargs["recipient"], "single-report-owner@example.com")
        self.assertNotEqual(send_mock.call_args.kwargs["recipient"], "tracked-contact@example.com")

    def test_manual_selected_summary_report_goes_to_user_not_tracked_contact(self) -> None:
        client = self.signup("selected-report-owner@example.com")
        self.connect_standard_mailbox(client, "selected-report-owner@example.com")
        contact_response = client.post("/whitelist", json={"contacts": ["tracked-contact@example.com"]})
        self.assertEqual(contact_response.status_code, 200, contact_response.text)

        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "selected-report-owner@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_combined_report_via_smtp(
                "selected_report_owner_example_com",
                "Selected Summary Report",
                "## tracked-contact@example.com\nImportant executive summary.",
            )

        send_mock.assert_called_once()
        self.assertEqual(send_mock.call_args.kwargs["recipient"], "selected-report-owner@example.com")
        self.assertNotEqual(send_mock.call_args.kwargs["recipient"], "tracked-contact@example.com")

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
            return_value={"recipient": "private-report@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_summary_via_smtp("private_report_example_com", secret_summary)

        send_kwargs = send_mock.call_args.kwargs
        serialized = json.dumps(send_kwargs)
        self.assertEqual(send_kwargs["subject"], dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT)
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
            return_value={"recipient": "private-combined@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_combined_report_via_smtp(
                "private_combined_example_com",
                "Board acquisition report",
                "## Secret section\nProject Falcon closes Friday.",
            )

        send_kwargs = send_mock.call_args.kwargs
        serialized = json.dumps(send_kwargs)
        self.assertEqual(send_kwargs["subject"], dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT)
        self.assertNotIn("Board acquisition report", serialized)
        self.assertNotIn("Project Falcon", serialized)
        self.assertIn("Private Notification", serialized)

    def test_combined_report_uses_executive_summary_only(self) -> None:
        markdown = dashboard_api.build_combined_report_markdown(
            [
                {
                    "summary_id": "summary_one",
                    "title": "Email Summary - Sender One",
                    "updated_at": "2026-04-30",
                    "executive_summary": "This is the executive summary.",
                    "action_items": "This action item should not be included.",
                    "bottom_line": "This bottom line should not be included.",
                },
                {
                    "summary_id": "summary_two",
                    "title": "Sender Two",
                    "new_developments": "This fallback section should not be included.",
                    "main_topics": "This topic should not be included.",
                },
            ]
        )

        self.assertIn("## Sender One", markdown)
        self.assertIn("This is the executive summary.", markdown)
        self.assertIn("## Sender Two", markdown)
        self.assertIn("No executive summary is available for this summary.", markdown)
        self.assertNotIn("This action item should not be included.", markdown)
        self.assertNotIn("This bottom line should not be included.", markdown)
        self.assertNotIn("This fallback section should not be included.", markdown)
        self.assertNotIn("This topic should not be included.", markdown)

    def test_selected_summary_email_cards_are_solid_white(self) -> None:
        html = dashboard_api.render_markdown_report_email_html(
            "Selected Summary Report",
            "## Sender One\nUpdated: 2026-04-30\nExecutive summary text.",
        )

        self.assertIn("background:#ffffff", html)
        self.assertNotIn("linear-gradient", html)
        self.assertNotIn("#f5f3ed", html)

    def test_report_email_formatter_removes_markdown_headings_and_escapes_html(self) -> None:
        html = dashboard_api.render_markdown_report_email_html(
            "Daily Report",
            "\n\n".join(
                [
                    "## Person One (person@example.com)",
                    "Updated: 2026-04-30",
                    "### Executive Summary",
                    "<script>alert('bad')</script>",
                    "### Action Items / Asks",
                    "- **Call** the client",
                    "### Empty Section",
                    "",
                    "## Person Two",
                    "### Bottom Line",
                    "No blockers.",
                ]
            ),
        )

        self.assertNotIn("###", html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;bad&#x27;)&lt;/script&gt;", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Action Items", html)
        self.assertIn("<strong>Call</strong> the client", html)
        self.assertIn("Person One", html)
        self.assertIn("person@example.com", html)
        self.assertNotIn("Empty Section", html)

    def test_report_email_text_is_readable_without_markdown_heading_markers(self) -> None:
        text = dashboard_api.render_markdown_report_text(
            "Daily Report",
            "## Person One\nUpdated: 2026-04-30\n### Executive Summary\nSummary text.\n### Deadlines / Dates / Meetings\n- Friday",
            max_chars=20000,
        )

        self.assertNotIn("###", text)
        self.assertNotIn("##", text)
        self.assertIn("Person One", text)
        self.assertIn("Executive Summary", text)
        self.assertIn("Dates & Deadlines", text)
        self.assertIn("- Friday", text)

    def test_refine_selected_summaries_persists_each_checked_summary(self) -> None:
        client = self.signup("batch-refine@example.com")
        user_id = "batch_refine_example_com"
        summaries_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        summaries_dir.mkdir(parents=True, exist_ok=True)
        first_summary = {
            "summary_id": "first_summary",
            "sender": "first@example.com",
            "title": "First Summary",
            "summary_markdown": "# First Summary\n\n## Executive Summary\nOld first executive.",
            "executive_summary": "Old first executive.",
        }
        second_summary = {
            "summary_id": "second_summary",
            "sender": "second@example.com",
            "title": "Second Summary",
            "summary_markdown": "# Second Summary\n\n## Executive Summary\nOld second executive.",
            "executive_summary": "Old second executive.",
        }
        (summaries_dir / "first_summary.json").write_text(json.dumps(first_summary), encoding="utf-8")
        (summaries_dir / "second_summary.json").write_text(json.dumps(second_summary), encoding="utf-8")

        mock_client = MagicMock()
        mock_client.responses.create.side_effect = [
            MagicMock(output_text="# First Summary\n\n## Executive Summary\nRefined first executive."),
            MagicMock(output_text="# Second Summary\n\n## Executive Summary\nRefined second executive."),
        ]

        with patch.object(dashboard_api, "OpenAI", return_value=mock_client):
            response = client.post(
                "/summaries/refine-selected",
                json={
                    "summary_ids": ["first_summary", "second_summary"],
                    "instructions": "Make these more concise.",
                    "save_preference": True,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["summary_ids"], ["first_summary", "second_summary"])
        self.assertEqual(mock_client.responses.create.call_count, 2)

        saved_first = json.loads((summaries_dir / "first_summary.json").read_text(encoding="utf-8"))
        saved_second = json.loads((summaries_dir / "second_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_first["executive_summary"], "Refined first executive.")
        self.assertEqual(saved_second["executive_summary"], "Refined second executive.")
        self.assertIn("Refined first executive.", saved_first["summary_markdown"])
        self.assertIn("Refined second executive.", saved_second["summary_markdown"])
        self.assertEqual(payload["summary_style_preferences"], ["Make these more concise."])

    def test_report_sender_config_resolves_from_report_env_vars(self) -> None:
        report_env = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
        }
        with patch.dict(os.environ, report_env):
            config = dashboard_api.get_report_sender_config()

        self.assertEqual(config["host"], "smtp.gmail.com")
        self.assertEqual(config["port"], 465)
        self.assertEqual(config["user"], "discere-sender@example.com")
        self.assertEqual(config["from_email"], "discere-sender@example.com")
        self.assertEqual(config["from_name"], "Discere")

    def test_missing_report_sender_password_returns_clean_configuration_error(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
        }
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")):
            with self.assertRaises(dashboard_api.HTTPException) as raised:
                dashboard_api.send_report_email_from_discere(
                    user_id="missing_password_user",
                    recipient="recipient@example.com",
                    subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                    html_body="<p>Ready</p>",
                    text_body="Ready",
                    event_name="test_missing_password",
                )

        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail["code"], "report_sender_not_configured")
        self.assertIn("Discere report email delivery needs attention", raised.exception.detail["message"])

    def test_report_sender_does_not_fallback_to_user_mailbox_smtp_credentials(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
            "SMTP_USER": "user-mailbox-smtp@example.com",
            "SMTP_PASSWORD": "user-mailbox-password",
        }
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")):
            config = dashboard_api.get_report_sender_config()

        self.assertNotEqual(config["user"], "user-mailbox-smtp@example.com")
        self.assertNotEqual(config["password"], "user-mailbox-password")
        self.assertEqual(config["from_email"], "discereresearch@gmail.com")
        self.assertEqual(config["user"], "discereresearch@gmail.com")

    def test_report_email_port_465_uses_smtp_ssl_and_discere_sender(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
            "EMAIL_SUMMARIZER_REPORT_REPLY_TO_EMAIL": "support@example.com",
        }
        server = MagicMock()
        smtp_ssl_context = MagicMock()
        smtp_ssl_context.__enter__.return_value = server
        smtp_ssl_context.__exit__.return_value = None
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")), patch.object(
            dashboard_api.smtplib,
            "SMTP_SSL",
            return_value=smtp_ssl_context,
        ) as smtp_ssl_mock, patch.object(dashboard_api.smtplib, "SMTP") as smtp_mock:
            delivery = dashboard_api.send_report_email_from_discere(
                user_id="smtp_ssl_user",
                recipient="recipient@example.com",
                subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                html_body="<p>Ready</p>",
                text_body="Ready",
                event_name="test_smtp_ssl",
            )

        smtp_ssl_mock.assert_called_once_with("smtp.gmail.com", 465, timeout=30)
        smtp_mock.assert_not_called()
        server.starttls.assert_not_called()
        server.login.assert_called_once_with("discere-sender@example.com", "test-app-password")
        sendmail_args = server.sendmail.call_args.args
        self.assertEqual(sendmail_args[0], "discere-sender@example.com")
        self.assertEqual(sendmail_args[1], ["recipient@example.com"])
        self.assertIn("From: Discere <discere-sender@example.com>", sendmail_args[2])
        self.assertIn("Reply-To: Discere <support@example.com>", sendmail_args[2])
        self.assertIn("Date:", sendmail_args[2])
        self.assertIn("Message-ID:", sendmail_args[2])
        decoded_message = decoded_mime_text(sendmail_args[2])
        self.assertIn("You received this because you requested or scheduled a Discere email summary.", decoded_message)
        self.assertIn("Need help? Contact", decoded_message)
        self.assertEqual(delivery["from"], "discere-sender@example.com")

    def test_scheduled_report_email_adds_manage_footer_and_list_unsubscribe(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
            "EMAIL_SUMMARIZER_REPORT_REPLY_TO_EMAIL": "support@example.com",
        }
        server = MagicMock()
        smtp_ssl_context = MagicMock()
        smtp_ssl_context.__enter__.return_value = server
        smtp_ssl_context.__exit__.return_value = None
        with patch.object(dashboard_api, "PUBLIC_BASE_URL", "https://discere-ai.com"), patch.object(
            dashboard_api,
            "get_app_config_value",
            side_effect=lambda key: config_values.get(key, ""),
        ), patch.object(
            dashboard_api.smtplib,
            "SMTP_SSL",
            return_value=smtp_ssl_context,
        ):
            dashboard_api.send_report_email_from_discere(
                user_id="scheduled_headers_user",
                recipient="recipient@example.com",
                subject="Morning Briefing - Scheduled Email Summary",
                html_body="<html><body><p>Ready</p></body></html>",
                text_body="Ready",
                event_name="test_scheduled_headers",
                include_manage_link=True,
            )

        message = server.sendmail.call_args.args[2]
        self.assertIn("List-Unsubscribe:", message)
        self.assertIn("https://discere-ai.com/settings", message)
        self.assertIn("Manage scheduled summaries in Discere settings", decoded_mime_text(message))

    def test_single_summary_email_html_escapes_summary_content(self) -> None:
        html = dashboard_api.render_summary_email_html(
            {
                "title": "<script>alert(1)</script>",
                "updated_at": "<b>today</b>",
                "executive_summary": "<img src=x onerror=alert(1)>\n- **Important** item",
            }
        )

        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertIn("<strong>Important</strong> item", html)

    def test_report_email_port_587_uses_starttls(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "587",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
        }
        server = MagicMock()
        smtp_context = MagicMock()
        smtp_context.__enter__.return_value = server
        smtp_context.__exit__.return_value = None
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")), patch.object(
            dashboard_api.smtplib,
            "SMTP",
            return_value=smtp_context,
        ) as smtp_mock, patch.object(dashboard_api.smtplib, "SMTP_SSL") as smtp_ssl_mock:
            dashboard_api.send_report_email_from_discere(
                user_id="smtp_starttls_user",
                recipient="recipient@example.com",
                subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                html_body="<p>Ready</p>",
                text_body="Ready",
                event_name="test_starttls",
            )

        smtp_mock.assert_called_once_with("smtp.gmail.com", 587, timeout=30)
        smtp_ssl_mock.assert_not_called()
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("discere-sender@example.com", "test-app-password")

    def test_report_email_auth_failure_does_not_expose_password(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
        }
        server = MagicMock()
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Username and Password not accepted")
        smtp_ssl_context = MagicMock()
        smtp_ssl_context.__enter__.return_value = server
        smtp_ssl_context.__exit__.return_value = None
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")), patch.object(
            dashboard_api.smtplib,
            "SMTP_SSL",
            return_value=smtp_ssl_context,
        ):
            with self.assertRaises(dashboard_api.HTTPException) as raised:
                dashboard_api.send_report_email_from_discere(
                    user_id="smtp_auth_user",
                    recipient="recipient@example.com",
                    subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                    html_body="<p>Ready</p>",
                    text_body="Ready",
                    event_name="test_auth_failure",
                )

        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(raised.exception.detail["code"], "smtp_auth_failed")
        self.assertIn("Discere report email delivery needs attention", raised.exception.detail["message"])
        self.assertNotIn("test-app-password", json.dumps(raised.exception.detail))

    def test_report_email_connection_failure_is_classified_cleanly(self) -> None:
        config_values = {
            "EMAIL_SUMMARIZER_REPORT_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PORT": "465",
            "EMAIL_SUMMARIZER_REPORT_SMTP_USER": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD": "test-app-password",
            "EMAIL_SUMMARIZER_REPORT_FROM_EMAIL": "discere-sender@example.com",
            "EMAIL_SUMMARIZER_REPORT_FROM_NAME": "Discere",
        }
        with patch.object(dashboard_api, "get_app_config_value", side_effect=lambda key: config_values.get(key, "")), patch.object(
            dashboard_api.smtplib,
            "SMTP_SSL",
            side_effect=dashboard_api.smtplib.SMTPConnectError(421, "temporarily unavailable"),
        ):
            with self.assertRaises(dashboard_api.HTTPException) as raised:
                dashboard_api.send_report_email_from_discere(
                    user_id="smtp_connection_user",
                    recipient="recipient@example.com",
                    subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                    html_body="<p>Ready</p>",
                    text_body="Ready",
                    event_name="test_connection_failure",
                )

        self.assertEqual(raised.exception.status_code, 502)
        self.assertEqual(raised.exception.detail["code"], "smtp_connection_failed")

    def test_report_email_rejects_invalid_recipient_before_smtp(self) -> None:
        with patch.object(dashboard_api.smtplib, "SMTP_SSL") as smtp_ssl_mock:
            with self.assertRaises(dashboard_api.HTTPException) as raised:
                dashboard_api.send_report_email_from_discere(
                    user_id="invalid_recipient_user",
                    recipient="not-an-email",
                    subject=dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT,
                    html_body="<p>Ready</p>",
                    text_body="Ready",
                    event_name="test_invalid_recipient",
                )

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("valid recipient email", raised.exception.detail)
        smtp_ssl_mock.assert_not_called()

    def test_manual_single_summary_email_subject_is_fixed(self) -> None:
        client = self.signup("manual-single-subject@example.com")
        summary = {
            "summary_id": "manual_single",
            "title": "Client-specific title should not become subject",
            "executive_summary": "Summary content.",
        }
        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "manual-single-subject@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_summary_via_smtp("manual_single_subject_example_com", summary)

        self.assertEqual(send_mock.call_args.kwargs["subject"], dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT)

    def test_manual_combined_report_email_subject_is_fixed(self) -> None:
        client = self.signup("manual-combined-subject@example.com")
        with patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "manual-combined-subject@example.com", "subject": dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT},
        ) as send_mock:
            dashboard_api.send_combined_report_via_smtp(
                "manual_combined_subject_example_com",
                "Combined Report (2 Selected)",
                "## Summary\nContent",
            )

        self.assertEqual(send_mock.call_args.kwargs["subject"], dashboard_api.MANUAL_REPORT_EMAIL_SUBJECT)

    def test_scheduled_report_subject_uses_schedule_name(self) -> None:
        self.assertEqual(
            dashboard_api.scheduled_report_email_subject("Morning Briefing"),
            "Morning Briefing - Scheduled Email Summary",
        )
        self.assertEqual(
            dashboard_api.scheduled_report_email_subject(""),
            dashboard_api.SCHEDULED_REPORT_EMAIL_FALLBACK_SUBJECT,
        )
        self.assertEqual(
            dashboard_api.scheduled_report_email_subject("Scheduled Report"),
            dashboard_api.SCHEDULED_REPORT_EMAIL_FALLBACK_SUBJECT,
        )

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

    def test_public_chat_is_unauthenticated_and_does_not_include_user_email_data(self) -> None:
        summaries_dir = dashboard_api.get_user_json_summaries_dir("private_user_example_com")
        summaries_dir.mkdir(parents=True, exist_ok=True)
        (summaries_dir / "private_summary.json").write_text(
            json.dumps(
                {
                    "summary_id": "private_summary",
                    "sender": "sender@example.com",
                    "title": "Private Summary",
                    "executive_summary": "Secret board meeting details should never appear in public chat context.",
                }
            ),
            encoding="utf-8",
        )

        mock_client = MagicMock()
        mock_client.responses.create.return_value = MagicMock(
            output_text="Discere helps you choose important senders, then summarizes those emails."
        )

        with patch.object(dashboard_api, "OpenAI", return_value=mock_client):
            response = self.client.post("/public-chat", json={"question": "How do I start?"})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Discere helps", response.json()["answer"])
        self.assertEqual(mock_client.responses.create.call_count, 1)
        input_text = mock_client.responses.create.call_args.kwargs["input"]
        self.assertIn("PUBLIC DISCERE KNOWLEDGE", input_text)
        self.assertNotIn("Secret board meeting", input_text)
        self.assertNotIn("private_user_example_com", input_text)
        instructions = mock_client.responses.create.call_args.kwargs["instructions"]
        self.assertIn("Do not use markdown formatting", instructions)

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
        self.assertEqual(send_mock.call_args.kwargs["subject"], "Daily - Scheduled Email Summary")

    def test_scheduled_report_new_summaries_are_visible_in_dashboard(self) -> None:
        client = self.signup("scheduled-dashboard@example.com")
        self.connect_standard_mailbox(client, "scheduled-dashboard@example.com")
        user_id = "scheduled_dashboard_example_com"
        contact = "sender@example.com"
        contacts_response = client.post("/whitelist", json={"contacts": [contact]})
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

        def fake_summarizer_run(_user_id: str, _days_back: int) -> dict:
            self.assertEqual(_user_id, user_id)
            summaries_dir = dashboard_api.get_user_json_summaries_dir(user_id)
            summaries_dir.mkdir(parents=True, exist_ok=True)
            summary = {
                "summary_id": "scheduled_visible_summary",
                "user_id": user_id,
                "sender": contact,
                "title": "Scheduled visible summary",
                "executive_summary": "This scheduled summary should become a dashboard card.",
                "created_at": "2026-04-28T08:00:00",
                "updated_at": "2026-04-28T08:00:00",
            }
            (summaries_dir / "scheduled_visible_summary.json").write_text(json.dumps(summary), encoding="utf-8")
            return {"success": True, "new_summary_ids": ["scheduled_visible_summary"]}

        with patch.object(dashboard_api, "execute_summarizer_run", side_effect=fake_summarizer_run), patch.object(
            dashboard_api,
            "send_combined_report_via_smtp",
            return_value={"recipient": "scheduled-dashboard@example.com"},
        ) as send_mock:
            dashboard_api.process_due_schedule(schedule_id)

        send_mock.assert_called_once()
        summaries_response = client.get("/summaries")
        self.assertEqual(summaries_response.status_code, 200, summaries_response.text)
        summaries = summaries_response.json()["summaries"]
        summary_ids = {summary["summary_id"] for summary in summaries}
        self.assertIn("scheduled_visible_summary", summary_ids)

    def test_scheduled_report_goes_to_user_not_tracked_contact(self) -> None:
        client = self.signup("scheduled-recipient-owner@example.com")
        self.connect_standard_mailbox(client, "scheduled-recipient-owner@example.com")
        user_id = "scheduled_recipient_owner_example_com"
        contact = "tracked-contact@example.com"
        contacts_response = client.post("/whitelist", json={"contacts": [contact]})
        self.assertEqual(contacts_response.status_code, 200, contacts_response.text)

        summaries_dir = dashboard_api.get_user_json_summaries_dir(user_id)
        summaries_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "summary_id": "scheduled_contact_summary",
            "sender": contact,
            "title": "Scheduled contact summary",
            "executive_summary": "This scheduled report should go to the account owner.",
            "created_at": "2026-04-28T08:00:00",
        }
        (summaries_dir / "scheduled_contact_summary.json").write_text(json.dumps(summary), encoding="utf-8")

        schedule_response = client.post(
            "/report-schedules",
            json={
                "name": "Daily",
                "recipient_email": contact,
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        self.assertEqual(schedule_response.status_code, 200, schedule_response.text)
        schedule = schedule_response.json()["schedule"]
        self.assertEqual(schedule["recipient_email"], "scheduled-recipient-owner@example.com")

        with patch.object(
            dashboard_api,
            "execute_summarizer_run",
            return_value={"success": True, "new_summary_ids": ["scheduled_contact_summary"]},
        ), patch.object(
            dashboard_api,
            "send_report_email_from_discere",
            return_value={"recipient": "scheduled-recipient-owner@example.com", "subject": "Daily - Scheduled Email Summary"},
        ) as send_mock:
            dashboard_api.process_due_schedule(schedule["schedule_id"])

        send_mock.assert_called_once()
        self.assertEqual(send_mock.call_args.kwargs["recipient"], "scheduled-recipient-owner@example.com")
        self.assertNotEqual(send_mock.call_args.kwargs["recipient"], contact)

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
            metadata={
                "api_key": "should-redact",
                "safe": "visible",
                "detail": (
                    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz "
                    "IMAP_PASSWORD=mailbox-secret "
                    '{"refresh_token":"refresh-secret","safe":"kept"}'
                ),
            },
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
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", serialized)
        self.assertNotIn("mailbox-secret", serialized)
        self.assertNotIn("refresh-secret", serialized)
        self.assertIn("visible", serialized)


if __name__ == "__main__":
    unittest.main()
