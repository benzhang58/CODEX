# Discere Project Context

Use this file to quickly brief another chat or developer on the Discere project.

## Product Summary

Discere is an email AI dashboard that lets users choose important contacts, scan recent emails from those contacts, and generate clean summaries. Users can read summaries in the dashboard, ask AI questions about saved summaries/emails, send themselves reports, and schedule recurring summary reports.

The product is designed for low-tech-skill users, especially business users who want simple email summaries without learning a complicated workflow.

## Current Product Logic

- Users add tracked contacts. Discere should only summarize emails from those tracked contacts.
- If there are no contacts, manual summarizer runs should tell the user to add contacts first.
- If a scheduled report has no contacts, it should skip the run, send no email, and advance to the next scheduled time.
- Summary cards are "new" until the user clicks/opens them.
- Checkboxes are only for actions like deleting, emailing, combining, or marking done.
- Read/done summaries are visually shaded darker than unread summaries.
- Marking a summary as done keeps it out of the normal summary flow.
- Deleting a summary removes its linked processed email IDs, so the email can be rediscovered if it still exists in the mailbox and falls within Days Back.
- Read or done summaries have source email bodies and saved attachments purged after 20 days, while summarized email IDs remain to prevent duplicate summaries.
- After purge, the summary remains, but the full thread/source body may no longer be available.
- Scheduled/manual report emails should be sent from Discere's report email system to the user's connected account email, not from the user's personal mailbox.
- Users can choose report mode: Full Report or Private Notification.
- SMS/Twilio/mobile delivery was explored but intentionally deferred/removed from the active scheduled reports UI because of cost/complexity.

## Authentication And Mailbox Access

Supported login/account paths:

- Google OAuth for Gmail users.
- Microsoft OAuth for Outlook/Hotmail/Microsoft 365 users.
- Standard account signup/login for other providers, such as 263.com, with separate mailbox connection credentials in Settings.

Important UX logic:

- Google/Microsoft OAuth users should not see the Mailbox Connection module in Settings.
- Standard/non-OAuth users should see Mailbox Connection and must connect mailbox credentials separately.
- Login Info shows whether the user signed in through Google OAuth, Microsoft OAuth, or Standard login.
- Existing valid sessions can auto-enter the dashboard.
- OAuth mailbox tokens must still refresh before summarizer runs; auto-login should not leave users with stale mailbox access.

## Data, Privacy, And Security Rules

- Account data must be scoped by `user_id`.
- One user must never see another user's contacts, summaries, settings, attachments, schedules, bug reports, analytics, or email-derived data.
- Google/Microsoft mailbox content is accessed only through the permissions granted by the user.
- Relevant email content is sent to OpenAI through the OpenAI API for summaries and AI answers.
- OpenAI API inputs/outputs are not used to train OpenAI models by default unless the API organization opts in, per OpenAI's published API data controls. Limited retention for abuse monitoring/safety may still apply.
- Attachment contents are sent to AI only if AI Attachment Access is turned on.
- If AI Attachment Access is off, only the email thread text and basic attachment metadata such as filenames should be used.
- OAuth tokens or mailbox credentials are encrypted and stored where needed.
- Production cookies should use `Secure=true`.
- Security pages/Privacy/Terms should accurately describe actual product behavior. Avoid overpromising.

## Billing And Subscription

Planned commercial model:

- One tier.
- 7-day free trial.
- $4.99/month after trial.
- No payment info required during trial.
- After trial expiration, users should be blocked until subscription is active.
- Owner/test accounts are exempt from billing limits.
- Stripe integration is scaffolded/ready conceptually, but live Stripe env vars and final checkout setup still need to be completed before charging real users.

## Usage Limits

Usage limits exist to prevent runaway OpenAI/API cost. Users should not see limit messaging unless they actually hit a cap. Limit-related UI should be clear and non-technical.

## Scheduled Reports

Scheduled reports should:

- Always run a fresh summarizer check for that account before sending.
- Only include newly generated summaries from that scheduled run.
- Never resend already summarized emails.
- Send nothing if there are no new summaries.
- Skip entirely if there are no contacts.
- Use the user's selected timezone and next-run logic.
- Save schedules with on/off toggle support.

## UI/UX Direction

General design direction:

- Minimal, polished, large, simple.
- Avoid technical jargon when possible.
- Buttons next to each other should align and usually share width/height.
- Modules/cards should be aligned and visually balanced.
- Older/less technical users should understand the text.
- The dashboard uses a soft card/bubble theme with bold typography.
- Background color choices should apply consistently across dashboard/settings backgrounds, not inside white cards/modules.

Key UX decisions:

- Contacts and AI Assistant are popup-style tools, not large permanent dashboard sections.
- Contacts are accessed from the Contacts dashboard card.
- AI Assistant should remember the conversation while the popup is closed/reopened during the same session.
- How To appears as a dashboard popup for first-time users, not as forced Settings navigation.
- The Settings How To should match the popup steps.
- Delete Account is at the bottom of Settings and should use an in-app confirmation modal.
- Admin Dashboard must not be accessible from normal user Settings/UI.

## Current Tech Stack

Primary app folder:

- `/Users/benzhang/Desktop/API/Email_Summarizer`

Main backend:

- `Email_Summarizer/dashboard_api.py`

Main frontend/static pages:

- `Email_Summarizer/dashboard_static/index.html`
- `Email_Summarizer/dashboard_static/settings.html`
- `Email_Summarizer/dashboard_static/login.html`
- `Email_Summarizer/dashboard_static/home.html`
- `Email_Summarizer/dashboard_static/privacy.html`
- `Email_Summarizer/dashboard_static/terms.html`
- `Email_Summarizer/dashboard_static/security.html`
- `Email_Summarizer/dashboard_static/how-to.html`

Main summarizer script:

- `Email_Summarizer/email_v13.py`

Regression tests:

- `Email_Summarizer/tests/test_security_regressions.py`

Database:

- SQLite.
- Render persistent disk path is expected around `/var/data/storage/app/app.db`.

Deployment:

- Render.
- Public domain intended to be `discere-ai.com`.
- Render service URL may still appear internally as `codex-vqm8.onrender.com`.

## Important Local Workflow Notes

- Use `rg` for searching.
- Use `apply_patch` for manual edits.
- Do not revert unrelated user changes.
- Do not commit secrets.
- Current untracked files may include `Discere_Logo.png` and `Email_Summarizer_Mobile/`; do not touch unless asked.
- Before pushing, run at least:
  - `python3 -m unittest Email_Summarizer.tests.test_security_regressions`
  - `python3 -m py_compile Email_Summarizer/dashboard_api.py Email_Summarizer/email_v13.py`
  - Static JS parse check for login/settings/index scripts.
  - `git diff --check`

## Recent/Active Work In This Thread

Recent changes have focused on:

- Microsoft OAuth consent/refresh failures returning clean messages.
- Standard account mailbox connection safeguards.
- Invalid contact email popup.
- Dashboard/settings background consistency.
- Scheduled report skip behavior when no contacts exist.
- Delete Account modal fix.
- In-progress optimization for View Full Thread/View Summary toggling to avoid slow refetch/re-render behavior.

If another chat is going to edit code, it should inspect `git status` and `git diff` first because there may be uncommitted work in progress.

## Documents Created For Planning

Project planning documents may exist in the repo, including:

- `LEGAL STUFF DOCUMENT`
- `PRICING STRATEGY`
- `NEXT STEPS TESTING IRL`

If exact filenames differ, search with `rg --files | rg -i "legal|pricing|next"`.

## High-Level Launch Checklist

Before broad commercial launch:

- Verify Google OAuth scopes and verification readiness.
- Verify Microsoft OAuth/publisher readiness.
- Finalize Stripe checkout and subscription handling.
- Review Terms/Privacy with an attorney.
- Confirm production env vars and no secrets in GitHub.
- Test account isolation with two real accounts.
- Test Gmail, Microsoft, and standard/263-style accounts end-to-end.
- Test manual summarizer, scheduled reports, report modes, AI assistant, deletion, purge, and billing gates.
- Confirm backup/restore plan for persistent database.
- Confirm production monitoring/readiness checks.
