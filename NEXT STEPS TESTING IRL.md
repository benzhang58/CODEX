# NEXT STEPS TESTING IRL

This is the practical checklist to run before publishing Discere publicly.

## 1. Production Smoke Test On Render

Test these with the production domain, not only localhost.

- Log in with a Gmail account.
- Add one contact.
- Run Summarizer.
- Confirm only tracked-contact emails are summarized.
- Open a summary and confirm it becomes read.
- Confirm unread/read shading works.
- Send a selected summary/report by email.
- Create a scheduled email report.
- Confirm the schedule appears in Saved Schedules.
- Turn the schedule off and on.
- Delete the schedule.
- Export account data from Settings.
- Delete the account from Settings.

Repeat with Microsoft:

- Log in with a Microsoft/Outlook account.
- Confirm Login Info shows Microsoft OAuth.
- Confirm Mailbox Connection is hidden for Microsoft OAuth accounts.
- Add one contact.
- Run Summarizer.
- Confirm the connected email shown is the clean Outlook email.
- Send a report by email.

Account isolation test:

- Use two real accounts in separate browsers or incognito windows.
- Account A adds contacts and generates summaries.
- Account B logs in and should not see Account A contacts, summaries, schedules, settings, bug reports, attachments, or profile info.
- Try manually changing URLs with Account A's `user_id` while logged into Account B. The app should block access.

## 2. OAuth Verification Readiness

Already done in the app/repo:

- Homepage exists at `/`.
- Privacy Policy exists at `/privacy`.
- Terms of Service exists at `/terms`.
- Security FAQ exists at `/security`.
- Homepage explains what Discere does.
- Public pages explain what data is read, what is stored, what is sent to AI, and how deletion works.
- README contains OAuth consent wording aligned to app behavior.
- Google/Microsoft OAuth redirect URLs are derivable from `EMAIL_SUMMARIZER_PUBLIC_BASE_URL`.

What still needs to be done manually in Google:

- Verify ownership of `discere-ai.com` in Google Search Console.
- In Google Cloud OAuth/App Branding, set:
  - App name: `Discere`
  - User support email: `discereresearch@gmail.com`
  - Homepage: `https://discere-ai.com/`
  - Privacy Policy: `https://discere-ai.com/privacy`
  - Terms of Service: `https://discere-ai.com/terms`
  - Authorized domain: `discere-ai.com`
  - Developer contact email: `discereresearch@gmail.com`
- In Google OAuth credentials, confirm redirect URI:
  - `https://discere-ai.com/auth/google/callback`
- Confirm requested scopes match the app:
  - `openid`
  - `email`
  - `profile`
  - `https://www.googleapis.com/auth/gmail.readonly`
  - `https://www.googleapis.com/auth/gmail.send`
- Prepare the scope justification:
  - Gmail read-only is used to find and summarize relevant emails from contacts selected by the user.
  - Gmail send is used only when the user requests emailed reports or scheduled emailed reports.
  - Profile/email is used for login and identifying the connected mailbox.
- Create the Google verification demo video.
  - Show homepage.
  - Show Google login.
  - Show consent screen.
  - Add a tracked contact.
  - Run Summarizer.
  - Open generated summary.
  - Send report by email.
  - Show Settings privacy controls/export/delete/account controls.

What still needs to be done manually in Microsoft:

- Confirm the Azure app registration is under a Microsoft Entra work/school tenant, not only a personal Microsoft account.
- Set publisher domain to `discere-ai.com`.
- Confirm redirect URI:
  - `https://discere-ai.com/auth/microsoft/callback`
- Confirm requested scopes match the app:
  - `openid`
  - `email`
  - `profile`
  - `offline_access`
  - `User.Read`
  - `Mail.Send`
  - `https://outlook.office.com/IMAP.AccessAsUser.All`
- For publisher verification, Microsoft currently requires a Microsoft AI Cloud Partner Program account with a valid Partner One ID and a verified publisher domain. If you do not have this yet, Microsoft may still work, but users may see unverified publisher messaging.
- If pursuing Microsoft publisher verification:
  - Use MFA.
  - Use an account with Application Administrator or Cloud Application Administrator role.
  - Use a Partner Center account with Microsoft AI Cloud Partner Program Admin or Accounts Admin role.
  - Add Partner One ID in App Registration > Branding & properties.

Useful official references:

- Google verification requirements: https://support.google.com/cloud/answer/13464321
- Google OAuth app verification submission: https://support.google.com/cloud/answer/13461325
- Microsoft publisher verification overview: https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview
- Microsoft mark app as publisher verified: https://learn.microsoft.com/en-us/entra/identity-platform/mark-app-as-publisher-verified

## 3. Legal / LLC / Insurance

Before charging businesses:

- Form LLC or intentionally stay in beta/sole-proprietor mode.
- Use the LLC name consistently in Terms, Privacy, Stripe, bank account, customer emails, and contracts.
- Keep business and personal finances separate.
- Get Terms and Privacy reviewed by an attorney.
- Get a cyber liability insurance quote.
- Get a general/professional liability insurance quote.
- Avoid healthcare, legal, finance, government, and other regulated-data customers until the product has stronger compliance controls.

## 4. Payment Setup

Before paid launch:

- Create Stripe account.
- Create `$9/month Early Access` plan.
- Decide whether the 7-day trial requires a credit card.
- Add billing/cancellation/refund language to Terms once Stripe is active.
- Add plan-based limits:
  - Free trial: lower limits.
  - Early Access: enough for normal usage, still capped.
  - Future Pro: higher limits.
- Test payment checkout and cancellation end-to-end.

## 5. Backup And Restore Test

Before launch:

- Run the backup script on Render:

```bash
cd /opt/render/project/src/Email_Summarizer
python3 scripts/backup_persistent_data.py \
  --storage-dir /var/data/storage \
  --output-dir /var/data/output \
  --backup-dir /var/data/backups
```

- Download the archive off Render.
- Restore it into a separate local/test environment.
- Confirm login, settings, contacts, summaries, schedules, and admin views still load.

## 6. Monitoring Check

Already checked locally:

- `/admin/monitoring` endpoint works.
- Monitoring events are stored.
- Sensitive-looking metadata keys are redacted.
- Cross-account access attempts are logged.
- Rate-limit events are logged.
- Oversized request events are logged.

Still test in production:

- Confirm `/admin` opens on Render.
- Confirm admin key or admin email works.
- Trigger a harmless failed login or invalid user access attempt.
- Confirm the event appears under Monitoring.
- Confirm `/health/readiness` shows `monitoring_enabled: true`.

## 7. Final Pre-Publish Go/No-Go

Publish only when:

- Google login works in production.
- Microsoft login works in production.
- Account isolation is confirmed with two real accounts.
- Export works.
- Delete account works.
- Backup and restore have been tested.
- Monitoring is visible in `/admin`.
- OAuth consent screens match app behavior.
- Terms/Privacy are reviewed or launch is explicitly marked Early Access/Beta.
