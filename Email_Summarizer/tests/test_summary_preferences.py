import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ["OPENAI_API_KEY"] = "test-openai-key"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import email_v13


class SummaryPreferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="discere-summary-preferences-")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_saved_summary_preferences_are_sent_to_summary_generation_prompt(self) -> None:
        captured = {}

        class FakeResponses:
            def create(self, **kwargs):
                captured.update(kwargs)
                return SimpleNamespace(output_text="## Executive Summary\nPreference applied.")

        class FakeOpenAI:
            def __init__(self, api_key):
                self.responses = FakeResponses()

        with patch.object(email_v13, "OpenAI", FakeOpenAI), patch.dict(
            os.environ,
            {
                "SUMMARY_STYLE_PREFERENCES": '["Focus heavily on deadlines", "Use shorter bullets"]',
                "WHITELIST_SENDERS": "boss@example.com",
            },
            clear=False,
        ):
            summarizer = email_v13.EmailSummarizer(Path(self.temp_dir), user_id="preference_test")
            record = email_v13.EmailRecord(
                uid=1,
                message_id="message-1",
                sender="boss@example.com",
                display_name="Boss",
                subject="Launch",
                date="2026-04-28",
                thread=[
                    email_v13.ThreadMessage(
                        message_id="message-1",
                        sender="boss@example.com",
                        to="user@example.com",
                        cc="",
                        subject="Launch",
                        date="2026-04-28",
                        body="Please launch by Friday.",
                    )
                ],
            )

            output = summarizer.generate_summary([record], contact_name="Boss (boss@example.com)")

        self.assertIn("Preference applied", output)
        prompt = captured.get("input", "")
        self.assertIn("USER SUMMARY STYLE PREFERENCES", prompt)
        self.assertIn("- Focus heavily on deadlines", prompt)
        self.assertIn("- Use shorter bullets", prompt)


if __name__ == "__main__":
    unittest.main()
