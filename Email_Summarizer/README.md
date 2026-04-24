# Email Summaries Dashboard

Local-first email summarization app with:

- FastAPI backend
- local browser dashboard
- SQLite-backed users/sessions/profiles
- per-user saved summaries and source email JSON
- optional Google OAuth sign-in scaffolding

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
- `EMAIL_SUMMARIZER_ADMIN_EMAILS` or `EMAIL_SUMMARIZER_ADMIN_KEY` if using admin views
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` if enabling Google sign-in
- `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` if enabling Microsoft sign-in

## Persistence

This app now separates code from runtime data.

- user/session/profile database:
  - `EMAIL_SUMMARIZER_STORAGE_DIR/app/app.db`
- per-user structured data:
  - `EMAIL_SUMMARIZER_STORAGE_DIR/users/...`
- legacy/raw summarizer outputs:
  - `EMAIL_SUMMARIZER_OUTPUT_DIR/...`

If you deploy this to Render, Railway, Fly, etc., mount persistent storage and point those two env vars at that mounted path.

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
- Google/Microsoft OAuth config present if using OAuth sign-in
- storage/output paths mounted
- database reachable
- rate limiting enabled

Security regression tests:

```bash
cd /Users/benzhang/Desktop/API
/Users/benzhang/fsl/bin/python3 -m unittest discover -s Email_Summarizer/tests
```

Admin inspection endpoints:

- `/admin/analytics`
- `/admin/bug-reports`

Set `EMAIL_SUMMARIZER_ADMIN_EMAILS` to comma-separated admin login emails, or use `EMAIL_SUMMARIZER_ADMIN_KEY` and send it as the `x-discere-admin-key` header.

## Current limitations

- Gmail OAuth is present for sign-in/token capture but not yet the full inbox-fetch path
- summaries/source emails are still stored as JSON on disk rather than in Postgres
- unread state is still browser-local
- SMTP delivery still depends on valid provider credentials

## Recommended next steps

1. Finish database-backed summarizer config loading end-to-end
2. Finish Gmail OAuth inbox access so Gmail users do not need IMAP app passwords
3. Move summary/email metadata into the database
4. Deploy behind a real public domain
