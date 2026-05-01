# Discere Context Page

Last updated: May 1, 2026

## Product Overview

Discere is an email AI dashboard that summarizes emails from high-importance people. The core idea is simple: users choose specific contacts they care about, then Discere checks recent emails from those contacts and creates clean summaries with key points, action items, dates, attachments, and bottom lines.

Discere is intentionally not meant to summarize an entire inbox by default. It is contact-focused. If a user has no tracked contacts, Discere should ask them to add contacts first rather than scanning broadly.

## Intended Public User Flow

Public users should log in with Gmail or Microsoft/Outlook. Discere should not publicly expose generic account creation or manual IMAP mailbox setup.

The normal flow is:

1. User visits the public home page.
2. User reads the simple overview or How To page.
3. User logs in with Gmail or Microsoft.
4. On first login, user accepts Terms and Privacy.
5. On first login, user sees the Getting Started popup.
6. If no profile name is saved, Discere asks for the user’s preferred name inside the app.
7. User adds tracked contacts.
8. User runs the summarizer.
9. User opens summaries, marks them done, deletes them, refines them, asks AI questions, sends selected reports, or schedules recurring reports.

## Special Manual Mailbox Flow

Public product direction is Gmail and Microsoft only.

Manual mailbox/263.com support is intended only for approved private clients. It should be hidden from normal users. The private manual signup flow is protected by a private access password and an allowlisted email list.

Current private access password default discussed in the project: `VIPCLIENT`.

Production should ideally override this with an environment variable rather than relying on the default.

Manual mailbox credentials must never be exposed to the browser, logs, GitHub, or API responses. If stored, they must be encrypted at rest using a stable production encryption key.

## Main App Pages

### Home Page

Path: `/`

Purpose: public marketing page. It should be simple and readable for non-technical users.

Main message:

Discere watches high-importance people in your inbox and turns their emails into clean, structured summaries.

Important behavior:

- Visiting `https://discere-ai.com` should show the home page even if the user is already logged in.
- Clicking `Log In` while already logged in should go straight to `/dashboard`.
- `Get Started` and `How It Works` should guide users to the How To page.

### How To Page

Path: `/how-to`

Purpose: teach users how to use Discere before or after logging in.

It should explain:

- Log in with Gmail or Microsoft.
- Add important contacts.
- Run the summarizer.
- Read summaries.
- Mark summaries done instead of deleting if the user wants Discere to remember the email was handled.
- Ask AI questions about saved summaries and email context.
- Send selected reports.
- Schedule recurring reports.
- Control attachment access and summary preferences.
- Delete account or report bugs.

The How To page should be concise, not overwhelming.

### Login Page

Path: `/login`

Purpose: public login.

Public login should show Gmail and Microsoft sign-in only.

If the user has a valid session, `/login` should redirect to `/dashboard`.

Manual login/password account flow should not be exposed publicly except through private manual-client routes.

### Private Signup Page

Path: `/manual-signup`

Purpose: approved private/manual mailbox clients only.

This is not part of the public user flow.

Access should require:

- Approved/allowlisted email.
- Private access password.

### Dashboard

Path: `/dashboard`

Purpose: main app interface after login.

Dashboard includes:

- Account bar with user name and settings/logout.
- Email Dashboard module.
- New Summaries count.
- Contacts card/button.
- AI Assistant card/button.
- Days Back.
- Current Time.
- Run Summarizer play button.
- Scheduled reports clock button.
- Status panel.
- Summary list.
- Summary detail view.

Expected dashboard behavior:

- Summaries are “new” until opened/read.
- Read summaries are shaded darker but should not resize.
- Checkboxes are for actions like sending selected reports, deleting, marking done, or refining.
- Clicking a summary opens it and marks it read.
- Contacts popup lets users add/remove contacts.
- AI Assistant opens as a popup and keeps conversation state while the popup closes/reopens.
- Run Summarizer should continue even if the user opens Settings or a popup.
- If a user runs summarizer with no contacts, show a popup asking them to add contacts first.

### Settings Page

Path: `/settings`

Purpose: account and preference management.

Settings includes:

- Profile Name.
- Login Info.
- Subscription.
- Summary Preferences.
- AI Attachment Access.
- Scheduled Summaries report mode.
- Background Color.
- Mailbox Connection only for private manual-mailbox allowlisted users.
- Legal links.
- Bug Reports.
- Delete Account at the bottom.

Settings should not show an Admin Dashboard link to normal users.

For Gmail/Microsoft users, Mailbox Connection should not appear.

## Summary Behavior

Discere summaries are generated from emails from tracked contacts only.

Each summary can include:

- Executive Summary.
- Main Topics / Key Points.
- New Developments / Updates.
- Action Items / Asks.
- Deadlines / Dates / Meetings.
- Attachment Summary.
- Bottom Line.

User-facing formatting should not show raw Markdown markers like `##`, `###`, or visible `**bold**` syntax. Dashboard summaries, email reports, and generated PDFs should render clean headings, text, bullets, and bold styling where appropriate.

Full Thread view is different from a generated summary. It shows saved source email thread content. If source email bodies were purged, Discere should show a clear message rather than trying to refetch or freezing.

## Read, Done, Delete, and Purging

Summaries are new until opened.

Read or done summaries keep the generated summary visible, but source email bodies and saved attachments are purged after the retention period.

Current retention target: 20 days.

Summarized email IDs remain after purge to prevent accidental duplicate summaries.

If a user deletes an individual summary, Discere removes the related saved identifier. This means that email can be rediscovered if the user runs the summarizer again.

Recommended user explanation:

Use Mark as Done when you want Discere to remember the email was handled. Delete only when you want the summary removed and are okay with that email being found again later.

If a new email arrives in the same thread, it should have a new message ID and can create a fresh summary.

## Contacts

Contacts are tracked senders. Adding a contact should never notify that contact.

Expected behavior:

- Adding a tracked contact sends no email to the contact.
- Summarizing emails from a contact sends no email to the contact.
- Manual and scheduled reports are sent only to the logged-in user’s connected account email.
- The tracked contact email should never be used as the report recipient.

## AI Assistant

AI Assistant should answer questions about:

- Saved summaries.
- Saved email context where available.
- Attachments where metadata/content is available.
- How Discere works.
- Privacy, security, Terms, report sending, retention, deletion, scheduled reports, and why deleted summaries can reappear.

AI Assistant should not answer from another user’s data.

## Summary Preferences and Refine Summary

Summary Preferences are reusable instructions applied to future summaries.

Refine Summary applies to selected/checkmarked summaries, not just the currently open one.

Refine Summary modal should say:

“How would you like the selected summary item(s) rewritten? Your saved summary preferences will also be applied.”

It should not list all saved preferences in the modal because that can look messy if many preferences exist.

## Report Sending

Discere report emails are sent from Discere’s configured report sender account, not from the user’s Gmail, Microsoft, or mailbox account.

Recipient should be the logged-in user’s connected account email.

Manual report subject:

`Discere - Email Summary`

Scheduled report subject:

`<schedule name> - Scheduled Email Summary`

Fallback scheduled subject:

`Discere - Scheduled Email Summary`

Report email modes:

- Full Report: includes summary content in the email.
- Email Notification: sends a simple notification/link without summary content.

Private Notification/Email Notification is the privacy-friendly option.

Manual selected report behavior:

- User checks one or more summary cards.
- Clicking Send Selected Report sends one email containing the Executive Summary sections from selected summaries.
- If no summary is selected, show an in-app popup telling the user to select an email summary using the checkbox.

Single full-summary send behavior:

- Sends the full summary for the currently open summary only.

Scheduled report behavior:

- Scheduled reports should run a fresh summarizer check first.
- Scheduled reports should include only newly generated summaries from that scheduled run.
- Scheduled reports should not repeat already summarized emails.
- If a scheduled report has no contacts, it should skip and send no email.
- Saved schedules should be editable, deletable, and toggleable on/off.

## Email Formatting

Emails should look polished and product-quality.

Requirements:

- No visible Markdown heading syntax like `###`.
- Clean Discere header.
- Short intro line.
- One card/block per contact or summary.
- Styled section headings.
- Readable spacing.
- Plain-text fallback.
- Inline CSS only.
- No JavaScript or external CSS.
- No empty section headings.
- Escape unsafe HTML.

## SMS / Text Delivery

SMS/Twilio was explored but intentionally paused because it costs money and adds complexity.

Text-specific UI should be hidden for now. Backend remnants can remain for future implementation if not exposed publicly.

Future SMS plan:

- Use Twilio or similar provider.
- SMS should send a short message with a PDF/report link.
- PDF should be formatted cleanly.

## Subscriptions and Billing

Current product direction:

- One tier.
- 7-day free trial.
- $4.99/month afterward.
- No payment info needed for trial.
- After trial ends, user must subscribe to continue.

Admin/test emails are exempt:

- `bnzhang2001@gmail.com`
- `bnnzhang2001@outlook.com`
- `peter@yj-semitech.com`

Settings should show Subscription status:

- Free Trial.
- Member.
- Trial ended / subscription required.

Stripe is intended but may not be fully configured yet. User-facing billing should be professional and simple.

## Usage Limits

Usage limits exist to prevent runaway OpenAI/API cost and abuse.

Users should not see usage limit information unless they hit a limit.

Limit-reached UI should be clear and non-technical.

## Analytics and Bug Reports

Analytics events include:

- Signup conversion.
- First summary generated.
- Contact added.
- Scheduled report created.
- Report delivered.
- Summary opened.
- Refinement used.

Bug reports are stored in the backend database and viewable through admin-only backend/admin endpoints with an admin key. Normal users should not have Admin Dashboard access.

## Admin Access

Admin dashboard/tools must not be visible or accessible to normal users through the UI.

Admin endpoints should require an admin key.

Do not expose admin keys to frontend JavaScript.

## Privacy Model

Discere reads email data needed to summarize messages from contacts the user chooses.

Discere stores:

- Account email and sign-in method.
- Profile name.
- Settings.
- Tracked contacts.
- Summaries.
- Schedules.
- Summary preferences.
- Limited source email data needed for full thread view before purge.
- Summarized email IDs to avoid accidental duplicates.
- OAuth tokens or mailbox credentials where needed, encrypted.
- Operational logs, bug reports, analytics events.

Discere sends relevant summary inputs to OpenAI through the OpenAI API.

OpenAI API note:

OpenAI states that API inputs and outputs are not used to train or improve OpenAI models by default unless the API organization explicitly opts in. OpenAI may still retain limited API data for abuse monitoring and safety under its published API data controls.

Attachment contents are sent to AI only if AI Attachment Access is turned on. If off, Discere may use attachment names/metadata but not attachment contents.

Report emails are sent from Discere to the user’s connected account email. If Full Report mode is selected, the report email contains summary content. If Email Notification mode is selected, the email does not include summary content.

Discere should not sell Google or Microsoft user data, use mailbox data for advertising, or transfer mailbox data except as needed to operate requested features, secure the product, comply with law, or protect users/service.

## Security Model

Security expectations:

- Account data must be scoped by `user_id`.
- One user must never see another user’s contacts, summaries, settings, schedules, attachments, source emails, OAuth tokens, mailbox credentials, analytics, or bug reports.
- OAuth tokens are encrypted at rest.
- Manual mailbox credentials, where used, are encrypted at rest.
- Login passwords for manual/private accounts are salted and hashed, never stored raw.
- Secrets should never be returned to frontend or logged.
- Production cookies should be `HttpOnly`, `Secure=true`, `SameSite=Lax`.
- Session cookie name: `email_dashboard_session`.
- Default session lifetime should remain 7 days, refreshed when users keep using Discere.
- `EMAIL_SUMMARIZER_ENCRYPTION_KEY` must be stable in production so encrypted credentials/tokens remain decryptable after deploys.
- Production readiness should fail or warn if critical security env vars are missing.
- Account deletion should delete user data and clear session.

Security claims should be accurate and not exaggerated. Avoid saying “zero risk.”

## OAuth Model

Gmail OAuth:

- Uses Gmail API read-only access.
- Used to identify Gmail address and read relevant mailbox content for summaries.
- Discere should not request Gmail send scope because reports are sent from Discere’s report sender account, not the user’s Gmail.

Microsoft OAuth:

- Uses Microsoft OAuth and Microsoft Graph mailbox access.
- Required mail scope: `https://graph.microsoft.com/Mail.Read`.
- Uses refresh/offline access so scheduled reports can run.
- Should not require unnecessary scopes like Microsoft Graph `User.Read` if identity can be resolved without it.

OAuth users should not see Mailbox Connection settings.

If OAuth access expires, is revoked, or lacks scope, show a clean reconnect message. Do not show raw tracebacks.

## Data Persistence and Deployment

Production runs on Render.

Expected persistent database path is on Render persistent disk, around:

`/var/data/storage/app/app.db`

User data should survive deploys if the SQLite database and storage directory are on the persistent disk.

Development/staging should ideally use separate Render services and separate storage/database from production.

`discere-ai.com` should point to stable production only.

Staging should use a separate Render URL/domain and separate OAuth redirect URIs.

## Important Environment Variables

Common production vars:

- `EMAIL_SUMMARIZER_PUBLIC_BASE_URL=https://discere-ai.com`
- `EMAIL_SUMMARIZER_STORAGE_DIR=/var/data/storage/app`
- `EMAIL_SUMMARIZER_ENCRYPTION_KEY=<stable strong secret>`
- `EMAIL_SUMMARIZER_COOKIE_SECURE=true`
- `EMAIL_SUMMARIZER_COOKIE_DOMAIN=` blank unless intentionally supporting both www and non-www
- `EMAIL_SUMMARIZER_SESSION_COOKIE_MAX_AGE_SECONDS=604800` for 7 days
- `OPENAI_API_KEY=<secret>`
- Google OAuth client ID/secret/redirect URI.
- Microsoft client ID/secret/tenant/redirect URI.
- Report sender SMTP settings.
- Admin key for admin-only endpoints.
- Manual mailbox allowlist/password only if private manual clients are enabled.

Report sender vars:

- `EMAIL_SUMMARIZER_REPORT_SMTP_HOST`
- `EMAIL_SUMMARIZER_REPORT_SMTP_PORT`
- `EMAIL_SUMMARIZER_REPORT_SMTP_USER`
- `EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD`
- `EMAIL_SUMMARIZER_REPORT_FROM_EMAIL`
- `EMAIL_SUMMARIZER_REPORT_FROM_NAME`
- Optional `EMAIL_SUMMARIZER_REPORT_REPLY_TO_EMAIL`

## Legal / Terms / Privacy / Security Pages

Public pages:

- `/privacy`
- `/terms`
- `/security`
- `/how-to`

Tone should be professional, clear, and understandable to non-technical users.

Avoid phrases like “the app” or “the product” when possible. Use “Discere” or “we.”

Privacy page should explain:

- What Discere reads.
- What Discere stores.
- What goes to AI.
- How report emails work.
- How deletion and retention work.
- Who can see data.
- Google/Microsoft OAuth use.
- OpenAI API data handling.
- Security limits and realistic risks.

Security FAQ should explain:

- Who can see data.
- Whether contacts are notified.
- Whether attachments go to AI.
- How long source email data is kept.
- How reports are sent.
- Main realistic risks.
- What users should avoid using Discere for until stronger compliance exists.

Terms should include:

- Acceptance.
- Eligibility.
- User responsibilities.
- Connected mailbox authorization.
- AI output disclaimer.
- Third-party services.
- Subscription/trial/payment terms.
- Account deletion/termination.
- Warranty disclaimer.
- Limitation of liability.
- Dispute law/venue language.

Legal docs should still be reviewed by a qualified attorney before broad commercial launch.

## Business / Launch Notes

Before commercial launch:

- Form LLC or intentionally beta-test as current business structure.
- Attorney review of Terms/Privacy.
- Finalize OAuth verification readiness.
- Confirm Google and Microsoft consent screens match actual app behavior.
- Confirm production persistence.
- Confirm account isolation with two real accounts.
- Confirm account deletion works.
- Confirm backup/restore plan.
- Set up production error monitoring.
- Set up transactional email provider with domain authentication.
- Set up Stripe when ready to charge.
- Test Gmail, Microsoft, and private manual client flows separately.

Recommended transactional email future direction:

- Use Postmark or Resend.
- Send from domain-authenticated address like `summaries@discere-ai.com`.
- Add SPF, DKIM, DMARC.
- Keep using SMTP-compatible provider first for smallest code/config change.

## Testing Checklist

Core tests:

- Gmail login first time.
- Microsoft login first time.
- Terms acceptance appears only first time.
- Name prompt appears only when no name is saved.
- How To popup appears only first time unless opened manually.
- Add/remove contacts.
- Removing last contact does not restore old contacts.
- Run summarizer with no contacts shows popup.
- Run summarizer with contacts creates summaries only from tracked senders.
- No cross-account data leakage.
- Open summary marks read.
- Read summary stays same size and only shading changes.
- Mark done persists.
- Delete summary allows rediscovery.
- View Summary / View Full Thread toggles smoothly.
- Refine selected summaries.
- Send Selected Report with no selection shows popup.
- Send Selected Report sends only selected executive summaries.
- Single summary email sends full selected summary.
- Scheduled report creates fresh run and emails only new summaries.
- Scheduled report with no contacts skips email.
- Private Notification mode sends no summary content.
- AI Attachment Access toggles and persists.
- Summary Preferences apply to new/refined summaries.
- Bug report stores correctly.
- Account deletion works and clears session.
- Logout confirmation uses in-app modal.
- No browser-native alerts/confirms/prompts.

Security tests:

- OAuth tokens never appear in frontend responses.
- Manual mailbox passwords never appear in frontend responses.
- Secrets redacted in logs/monitoring.
- Production cookies secure.
- Readiness endpoint has no critical errors.
- Admin endpoints require admin key.

