# MOMDADPLAN

## 1. Current Findings

SQLite is configured correctly if Render is actually using the current `render.yaml` setup.

Current production-intended paths:

- Database: `/var/data/storage/app/app.db`
- User storage: `/var/data/storage/users/...`
- Public reports: `/var/data/storage/public_reports`
- Legacy/output files: `/var/data/output/...`
- Render disk mount: `/var/data`

In code:

- `EMAIL_SUMMARIZER_STORAGE_DIR` defaults locally to `Email_Summarizer/data`
- `EMAIL_SUMMARIZER_OUTPUT_DIR` defaults locally to `Email_Summarizer/email_summaries_output`
- In `render.yaml`, they are set to:
- `EMAIL_SUMMARIZER_STORAGE_DIR=/var/data/storage`
- `EMAIL_SUMMARIZER_OUTPUT_DIR=/var/data/output`
- disk mounted at `/var/data`

If Render deployed from `render.yaml`, user data should survive deploys.

Data locations:

- Accounts: SQLite `users`
- Contacts: encrypted `users.settings_json`, keys `WHITELIST_SENDERS` and `CONTACT_PROFILES`
- Settings: encrypted `users.settings_json`
- Report schedules: SQLite `report_schedules`
- Sessions: SQLite `sessions`, plus browser cookie `email_dashboard_session`
- OAuth tokens: encrypted `users.google_oauth_json` / `users.microsoft_oauth_json`
- Mailbox credentials: encrypted inside `users.settings_json`
- Summaries: mostly files in `/var/data/storage/users/{user_id}/summaries`
- Source email bodies/thread JSON: `/var/data/storage/users/{user_id}/emails`
- Processed email IDs: `/var/data/output/{user_id}/processed_state.json`
- Attachments: `/var/data/output/{user_id}/attachments`
- Bug reports/analytics/usage counters: SQLite

I did not find startup logic that intentionally wipes user data. Startup uses `CREATE TABLE IF NOT EXISTS`, safe `ALTER TABLE`, and legacy encryption/migration. The destructive paths are user-triggered account deletion, schedule deletion, summary deletion, and retention purging of old read/done source content.

Sessions should survive deploys if:

- `/var/data/storage/app/app.db` persists
- browser keeps the cookie
- cookie name/domain remains stable
- session cookie has not expired

Sessions are not guaranteed forever. Current cookie max age is 7 days. Users may need to log in again after cookie expiry, browser cleanup, domain changes, or if the DB path changes. Their account data should still remain saved.

## 2. Recommended Approach

Do not do per-email frozen app versions inside one app. That creates brittle logic and makes debugging/security harder.

Use this architecture instead:

- `discere-ai.com` = stable production app
- Separate Render staging/dev service = where new changes are tested
- Production and staging should have separate storage disks/databases
- Production should only get pushed/deployed after staging is tested
- Mom/dad should use production only

This is the normal SaaS pattern. It protects real users from dev changes without building per-account code-version logic.

For now, SQLite on Render persistent disk is acceptable for early private/beta usage. Before heavier commercial usage, consider managed Postgres because it is safer for concurrency, backups, observability, and long-term reliability.

## 3. Proposed Implementation Steps

1. Confirm current production Render service is using persistent disk:
   - Disk mounted at `/var/data`
   - `EMAIL_SUMMARIZER_STORAGE_DIR=/var/data/storage`
   - `EMAIL_SUMMARIZER_OUTPUT_DIR=/var/data/output`

2. Add or verify a production persistence health check:
   - Confirm `/health/readiness` shows storage writable, output writable, database reachable.
   - Optionally add a clearer field showing exact `DB_PATH`.

3. Create a separate staging Render service:
   - Same repo, but deploy from a dev branch or staging branch.
   - Separate disk mounted at `/var/data`.
   - Separate env vars.
   - Separate custom domain optional, such as `staging.discere-ai.com`, or just use the Render URL.

4. Keep production deploys controlled:
   - Develop locally.
   - Push to GitHub.
   - Deploy/test staging.
   - Only then merge/deploy production.

5. Add backup routine before family/real users rely on it:
   - Run existing `scripts/backup_persistent_data.py`.
   - Download backup off Render disk.
   - Test restore at least once.

6. Add a simple production data persistence smoke test:
   - Create test account.
   - Add contact.
   - Add schedule.
   - Generate/read summary.
   - Redeploy.
   - Confirm data still exists.

## 4. Render Configuration Checklist

Production Render service:

- Disk mount path: `/var/data`
- Disk size: at least `10GB` for now

Required production env vars:

```text
EMAIL_SUMMARIZER_STORAGE_DIR=/var/data/storage
EMAIL_SUMMARIZER_OUTPUT_DIR=/var/data/output
EMAIL_SUMMARIZER_PUBLIC_BASE_URL=https://discere-ai.com
EMAIL_SUMMARIZER_COOKIE_SECURE=true
EMAIL_SUMMARIZER_COOKIE_DOMAIN=
EMAIL_SUMMARIZER_ENCRYPTION_KEY=<stable secret, never rotate casually>
OPENAI_API_KEY=<secret>
```

OAuth production callbacks:

```text
GOOGLE_REDIRECT_URI=https://discere-ai.com/auth/google/callback
MICROSOFT_REDIRECT_URI=https://discere-ai.com/auth/microsoft/callback
```

Staging callbacks should be different:

```text
GOOGLE_REDIRECT_URI=https://your-staging.onrender.com/auth/google/callback
MICROSOFT_REDIRECT_URI=https://your-staging.onrender.com/auth/microsoft/callback
```

OAuth apps:

- Same Google/Microsoft app can support multiple redirect URIs.
- Cleaner long-term: separate OAuth apps for production and staging.
- For verification/public trust, production OAuth should be clean and stable.

Report sender:

- Production can use the real Discere sender.
- Staging should ideally use a separate test sender or have report sending disabled, so tests do not accidentally email real users.

## 5. Risks / Decisions To Approve

Main likely reason for resets:

- Render service may not actually be using the persistent disk/env path.
- Or a new Render service/deploy was created without the same disk.
- Or local testing is being confused with production because local uses a different DB path.

Important decisions:

- Approve creating a separate staging Render service.
- Decide whether staging uses same OAuth apps or separate OAuth apps.
- Decide whether staging email sending is disabled or uses separate test SMTP.
- Decide backup cadence before family relies on it.
- Decide whether SQLite is enough for beta or whether to move to Postgres before public launch.

Do not implement per-email frozen versions. Use stable production plus staging.

## 6. Manual Test Plan

Production persistence test:

1. Log into `discere-ai.com`.
2. Add one test contact.
3. Add one summary preference.
4. Create one schedule.
5. Run summarizer if possible.
6. Log out and log back in.
7. Confirm contact/settings/schedule remain.
8. Trigger a Render redeploy.
9. Log back in.
10. Confirm contact/settings/schedule/summaries remain.

Session test:

1. Log in.
2. Close browser tab.
3. Reopen `discere-ai.com/login`.
4. Confirm it goes to dashboard if cookie is still valid.
5. Retest after redeploy.
6. If logged out, log back in and confirm account data remains.

Data isolation test:

1. Create/login Account A.
2. Add contacts/schedule/summary.
3. Log out.
4. Login Account B.
5. Confirm Account B sees none of Account A's contacts, schedules, summaries, settings, or bug reports.

Render verification:

1. Open `https://discere-ai.com/health/readiness`.
2. Confirm:
   - `storage_dir_writable: true`
   - `output_dir_writable: true`
   - `database_reachable: true`
   - `cookie_secure: true`
   - no critical errors

Before implementation, verify in Render that the current live service has a persistent disk mounted at `/var/data` and that the env vars point to `/var/data/storage` and `/var/data/output`.
