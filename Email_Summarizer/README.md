# Email Summaries Dashboard

Local-first email summarization app with:

- FastAPI backend
- local browser dashboard
- SQLite-backed users/sessions/profiles
- per-user saved summaries and source email JSON
- Google and Microsoft OAuth sign-in and mailbox access

## Current architecture

- Web app: [dashboard_api.py](/Users/benzhang/Desktop/API/Email_Summarizer/dashboard_api.py)
- Summarizer worker: [email_v13.py](/Users/benzhang/Desktop/API/Email_Summarizer/email_v13.py)
- Frontend: [dashboard_static/index.html](/Users/benzhang/Desktop/API/Email_Summarizer/dashboard_static/index.html)
- Login page: [dashboard_static/login.html](/Users/benzhang/Desktop/API/Email_Summarizer/dashboard_static/login.html)
- Signup page: [dashboard_static/signup.html](/Users/benzhang/Desktop/API/Email_Summarizer/dashboard_static/signup.html)

## Local run

1. Copy `.env.example` to `.env` and fill in real values.
2. Install dependencies:

```bash
cd /Users/benzhang/Desktop/API/Email_Summarizer
python3 -m pip install -r requirements.txt
```

3. Start the app:

```bash
python3 -m uvicorn dashboard_api:app --host 127.0.0.1 --port 8000
```

4. Open:

- [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)

## Hosted deployment requirements

To make this accessible to other people, the host needs:

- Python environment with the packages from `requirements.txt`
- persistent disk for:
  - SQLite database
  - stored email/source JSON
  - generated summaries
  - attachments
- app-level environment variables

Recommended environment variables:

- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `EMAIL_SUMMARIZER_STORAGE_DIR`
- `EMAIL_SUMMARIZER_OUTPUT_DIR`
- `EMAIL_SUMMARIZER_PUBLIC_BASE_URL`
- `EMAIL_SUMMARIZER_ENCRYPTION_KEY`
- `EMAIL_SUMMARIZER_ADMIN_KEY` for internal admin/monitoring API access
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` if enabling Google sign-in
- `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` if enabling Microsoft sign-in
- `EMAIL_SUMMARIZER_REPORT_SMTP_HOST=smtp.gmail.com`
- `EMAIL_SUMMARIZER_REPORT_SMTP_PORT=465`
- `EMAIL_SUMMARIZER_REPORT_SMTP_USER=discereresearch@gmail.com`
- `EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD=<Gmail app password or SMTP password>`
- `EMAIL_SUMMARIZER_REPORT_FROM_EMAIL=discereresearch@gmail.com`
- `EMAIL_SUMMARIZER_REPORT_FROM_NAME=Discere`

## Persistence

This app now separates code from runtime data.

- user/session/profile database:
  - `EMAIL_SUMMARIZER_STORAGE_DIR/app/app.db`
- per-user structured data:
  - `EMAIL_SUMMARIZER_STORAGE_DIR/users/...`
- legacy/raw summarizer outputs:
  - `EMAIL_SUMMARIZER_OUTPUT_DIR/...`

If you deploy this to Render, Railway, Fly, etc., mount persistent storage and point those two env vars at that mounted path.

## Subscription and billing scaffold

Discere currently includes a Stripe-ready billing scaffold:

- New accounts receive a 7-day no-card free trial.
- The first paid plan is shown as `$4.99/month`.
- Paid feature routes are enforced server-side after the trial ends.
- Testing/admin emails can be exempted with `EMAIL_SUMMARIZER_BILLING_EXEMPT_EMAILS`.
- Settings includes a Subscription card and a Manage Subscription action.

Current billing env vars:

```bash
EMAIL_SUMMARIZER_SUBSCRIPTION_TRIAL_DAYS=7
EMAIL_SUMMARIZER_SUBSCRIPTION_PRICE_CENTS=499
EMAIL_SUMMARIZER_SUBSCRIPTION_PRICE_LABEL="$4.99"
EMAIL_SUMMARIZER_BILLING_EXEMPT_EMAILS=bnzhang2001@gmail.com,bnnzhang2001@outlook.com,peter@yj-semitech.com
EMAIL_SUMMARIZER_STRIPE_CHECKOUT_URL=
EMAIL_SUMMARIZER_STRIPE_CUSTOMER_PORTAL_URL=
```

`EMAIL_SUMMARIZER_STRIPE_CHECKOUT_URL` and `EMAIL_SUMMARIZER_STRIPE_CUSTOMER_PORTAL_URL` are placeholders for the later Stripe integration. Until they are configured, the UI explains that checkout is not connected rather than pretending a payment succeeded.

## Backup and restore plan

The persistent disk is the source of truth for production state. Back up the whole disk state, not just the SQLite file.

What must be backed up:

- `EMAIL_SUMMARIZER_STORAGE_DIR/app/app.db`: users, sessions, profiles, schedules, analytics, bug reports, and usage counters
- `EMAIL_SUMMARIZER_STORAGE_DIR/app/email_summarizer.key`: local fallback encryption key if `EMAIL_SUMMARIZER_ENCRYPTION_KEY` is not set
- `EMAIL_SUMMARIZER_STORAGE_DIR/users/...`: per-user summaries, source email JSON, processed email IDs, and attachment metadata/files
- `EMAIL_SUMMARIZER_OUTPUT_DIR/...`: legacy summarizer output folders still used by older worker paths
- Render environment variables, especially `EMAIL_SUMMARIZER_ENCRYPTION_KEY`, OAuth secrets, OpenAI key, admin config, and public base URL

Create a backup from a Render shell:

```bash
cd /opt/render/project/src/Email_Summarizer
python3 scripts/backup_persistent_data.py \
  --storage-dir /var/data/storage \
  --output-dir /var/data/output \
  --backup-dir /var/data/backups
```

The script creates a timestamped `discere-backup-YYYYMMDDTHHMMSSZ.tar.gz` archive. It uses SQLite's online backup API so `app.db` is copied consistently while the app is running, then bundles user files and output folders into the same archive. The archive contains sensitive data and must be stored somewhere private.

Recommended operating cadence:

- Before launch: run a manual backup and restore test.
- During beta: back up at least daily and before any risky deployment.
- After paid/customer usage starts: automate daily backups and keep at least 14-30 days of history.
- After every backup: download or sync the archive off the Render disk. A backup stored only on the same disk does not protect against disk loss.

Restore outline:

1. Put the app in maintenance mode or stop the Render service.
2. Save a copy of the current `/var/data` folder before replacing anything.
3. Extract the backup archive into a temporary folder.
4. Restore `storage/app/app.db`, `storage/app/email_summarizer.key` if used, `storage/users`, and `output` into `/var/data`.
5. Confirm Render env vars match the backup, especially `EMAIL_SUMMARIZER_ENCRYPTION_KEY`.
6. Start the service and verify `/health/readiness`, login, contacts, summaries, schedules, and report delivery.

Do not commit backup archives. `.gitignore` excludes local backup folders and `.tar.gz` archives.

## Smallest hosted path

The repo now includes:

- [Dockerfile](/Users/benzhang/Desktop/API/Email_Summarizer/Dockerfile)
- [start.sh](/Users/benzhang/Desktop/API/Email_Summarizer/start.sh)
- [render.yaml](/Users/benzhang/Desktop/API/Email_Summarizer/render.yaml)

So the smallest path to put this in front of other people is:

1. Push the current repo to GitHub
2. Create a new Render web service from that repo
3. Use the included `render.yaml`
4. Add the missing secret env vars in Render
5. Set `EMAIL_SUMMARIZER_PUBLIC_BASE_URL` to the real Render URL or your custom domain
6. Mount the persistent disk at `/var/data`

That gets you a public app with persistent storage, but not yet production-grade mail auth.

After deploy, verify:

- [https://your-domain.example.com/health](https://your-domain.example.com/health)
- [https://your-domain.example.com/health/deployment](https://your-domain.example.com/health/deployment)
- [https://your-domain.example.com/health/readiness](https://your-domain.example.com/health/readiness)

The deployment/readiness endpoints should confirm:

- public base URL configured
- OpenAI key present
- encrypted profile storage key present
- secure production cookies enabled
- security headers enabled
- production CORS origins are HTTPS-only and do not use `*`
- Google/Microsoft OAuth config present if using OAuth sign-in
- Discere report sender SMTP credentials configured
- storage/output paths mounted
- database reachable
- rate limiting enabled

Usage limits are enforced per account per UTC day. Defaults:

- `EMAIL_SUMMARIZER_LIMIT_RUN_SUMMARIZER_PER_DAY=10`
- `EMAIL_SUMMARIZER_LIMIT_SCHEDULED_REPORTS_PER_DAY=24`
- `EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY=100`
- `EMAIL_SUMMARIZER_LIMIT_REFINE_PER_DAY=30`
- `EMAIL_SUMMARIZER_LIMIT_REPORT_DELIVERY_PER_DAY=50`

Set a limit to `0` to make that action unlimited. The `/usage` endpoint shows the logged-in account's current daily usage.

## Public launch checklist

Before sending real users to the app:

1. Set `EMAIL_SUMMARIZER_PUBLIC_BASE_URL=https://discere-ai.com` in Render.
2. Set a long random `EMAIL_SUMMARIZER_ENCRYPTION_KEY` in Render and do not change it after users exist.
3. Set `EMAIL_SUMMARIZER_COOKIE_SECURE=true`.
4. Set `EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED=true`.
5. Set `EMAIL_SUMMARIZER_ADMIN_KEY` to a long random secret for internal admin/monitoring API access.
6. Set `OPENAI_API_KEY` and `OPENAI_MODEL=gpt-5.1`.
7. Confirm usage limit env vars match the beta/free tier you want.
8. Add `https://discere-ai.com/auth/google/callback` in Google OAuth credentials.
9. Add `https://discere-ai.com/auth/microsoft/callback` in Azure app registration.
10. Confirm `/health/readiness` returns `status: ready` or only expected OAuth warnings.
11. Run the security regression tests below before pushing launch changes.
12. Confirm account isolation manually with two real accounts before broad rollout.
13. Run `scripts/backup_persistent_data.py` on Render and download the archive off the Render disk.
14. Restore that archive into a separate test/local environment once, then verify login, summaries, schedules, and settings load.

Security regression tests:

```bash
cd /Users/benzhang/Desktop/API
/Users/benzhang/fsl/bin/python3 -m unittest discover -s Email_Summarizer/tests
```

Admin inspection endpoints:

- `/admin/analytics`
- `/admin/bug-reports`
- `/admin/monitoring`

Set `EMAIL_SUMMARIZER_ADMIN_KEY` and send it as the `x-discere-admin-key` header. There is no user-facing admin dashboard link or login-email-based admin access.

## Production monitoring

The app includes first-party monitoring in the SQLite database. It is not a full replacement for Sentry/PagerDuty, but it catches the most important launch risks without adding another vendor.

Set:

- `EMAIL_SUMMARIZER_MONITORING_ENABLED=true`

Monitoring records:

- OAuth callback/token/scope failures
- summarizer failures, timeouts, and mailbox/OpenAI error hints
- cross-account `user_id` override attempts and attachment access denials
- report delivery failures for email, PDFs, and the Discere report sender SMTP account
- rate-limit hits, oversized requests, and invalid request headers
- unhandled server exceptions and OpenAI chat/refine failures
- deletion/purge-related failures when surfaced as server errors

Admins can review events through the internal `/admin/monitoring` API using the `x-discere-admin-key` header. The readiness endpoint includes `recent_monitoring_alerts` from the last 24 hours. Metadata is redacted for sensitive-looking keys such as tokens, secrets, passwords, authorization headers, cookies, and API keys.

For later scale, add Sentry or another hosted error monitor for stack traces, alert routing, and uptime checks. Keep this internal monitoring anyway because it is product-aware and stores events alongside app state.

## OAuth consent screen alignment

The public website, privacy page, and OAuth consent screens should describe the same data use. Current app behavior:

- App purpose: Discere summarizes emails from contacts selected by the user.
- Google scopes: `openid`, `email`, `profile`, `https://www.googleapis.com/auth/gmail.readonly`.
- Microsoft scopes: `openid`, `email`, `profile`, `offline_access`, `User.Read`, `https://outlook.office.com/IMAP.AccessAsUser.All`.
- Gmail OAuth uses Gmail API read-only access to find emails from tracked contacts and build summaries.
- Microsoft OAuth uses Microsoft-supported IMAP mailbox access to find emails from tracked contacts and build summaries.
- Non-OAuth mailbox connections use the IMAP settings and mailbox credentials the user provides.
- Report emails are sent from the Discere report sender address, not from the connected user mailbox.
- Profile/email access is used to sign the user in, identify the connected mailbox, and display account information.
- Offline/refresh access is used so scheduled reports and recurring mailbox checks can run without forcing the user to sign in every time.
- Email/thread content needed for summaries is sent to the AI provider. Attachment contents are sent only when AI attachment access is enabled.
- OAuth tokens and mailbox credentials are stored encrypted.
- Google API data use should align with the Google API Services User Data Policy, including Limited Use requirements.
- Microsoft API and Microsoft-supported email protocol use should align with applicable Microsoft API terms and policies.
- Users can revoke provider access through Google Account permissions, Microsoft account consent management, or Microsoft My Apps, depending on provider and account type.

Suggested short consent/support description:

```text
Discere helps users summarize important emails from contacts they choose. It reads mailbox content needed to find and summarize relevant messages, sends requested reports from Discere's report sender address instead of from the user's connected mailbox, and uses profile/email access to sign users in and identify the connected mailbox.
```

## Current limitations

- summaries/source emails are still stored as JSON on disk rather than in Postgres
- unread state is still browser-local
- report email delivery depends on the Discere report sender SMTP credentials

## Recommended next steps

1. Finish database-backed summarizer config loading end-to-end
2. Test the full Google and Microsoft OAuth inbox summarizer flow in production
3. Move summary/email metadata into the database
4. Deploy behind a real public domain
