# NEXT STEPS TESTING IRL

This is the step-by-step checklist to run before publishing Discere publicly. Test these on the production Render/domain version, not only localhost.

## 1. Production Domain And Environment

- [ ] Open `https://discere-ai.com/` and confirm it loads the public homepage.
- [ ] Click `Get Started` and confirm it goes to `/login`.
- [ ] Confirm `/privacy`, `/terms`, and `/security` load from the public domain.
- [ ] Confirm the dashboard URL stays on the public domain after login, not the raw Render domain.
- [ ] In Render env vars, confirm `EMAIL_SUMMARIZER_PUBLIC_BASE_URL=https://discere-ai.com`.
- [ ] In Render env vars, confirm production secrets are present and not committed to GitHub.
- [ ] Confirm cookies are secure in production by checking `/health/readiness` shows `cookie_secure: true`.
- [ ] Confirm `/health/readiness` has no critical errors.

## 2. Gmail Account Test

Use a real Gmail account with test emails available.

- [ ] Log in with Gmail.
- [ ] Confirm the OAuth consent screen shows the correct app name: `Discere`.
- [ ] Confirm the OAuth consent screen asks for only the scopes the app actually needs.
- [ ] Confirm the dashboard shows the clean Gmail email address.
- [ ] Confirm Settings shows `Google OAuth`.
- [ ] Confirm Mailbox Connection is hidden for Gmail OAuth users.
- [ ] Add one tracked contact.
- [ ] Run Summarizer.
- [ ] Confirm only emails from tracked contacts are summarized.
- [ ] Confirm unrelated emails are not summarized.
- [ ] Open a summary.
- [ ] Confirm it becomes read only after opening it.
- [ ] Confirm read summaries have darker shading and unread summaries are lighter.
- [ ] Select one or more summaries.
- [ ] Generate a combined report.
- [ ] Send the report by email.
- [ ] Confirm the email arrives in the connected Gmail inbox.
- [ ] Use AI Assistant and ask a basic question about saved summaries.
- [ ] Use Refine Summary and confirm it returns a refined version.
- [ ] Toggle AI Attachment Access on, leave Settings, return to Settings, and confirm it stays on.
- [ ] Toggle AI Attachment Access off and confirm it stays off.
- [ ] Export account data from Settings.
- [ ] Delete the account from Settings after testing, or keep it as a test account.

## 3. Microsoft / Outlook Account Test

Use a real Outlook/Microsoft account.

- [ ] Log in with Microsoft.
- [ ] Confirm the OAuth consent screen shows the correct app name: `Discere`.
- [ ] Confirm the OAuth consent screen asks for only the scopes the app actually needs.
- [ ] Confirm the dashboard shows a clean Outlook email address.
- [ ] Confirm Settings shows `Microsoft OAuth`.
- [ ] Confirm Mailbox Connection is hidden for Microsoft OAuth users.
- [ ] Add one tracked contact.
- [ ] Run Summarizer.
- [ ] Confirm only emails from tracked contacts are summarized.
- [ ] Open a summary and confirm it becomes read.
- [ ] Send a selected summary/report by email.
- [ ] Confirm the report arrives in the connected Outlook inbox.
- [ ] Create a scheduled email report.
- [ ] Confirm the schedule appears in Saved Schedules.
- [ ] Turn the schedule off.
- [ ] Turn the schedule back on.
- [ ] Edit the schedule.
- [ ] Delete the schedule.
- [ ] Export account data from Settings.
- [ ] Delete the account from Settings after testing, or keep it as a test account.

## 4. Standard / 263 / Password Account Test

Use this for non-Gmail/non-Microsoft mailbox users.

- [ ] Create a standard account from `/signup`.
- [ ] Confirm Terms and Privacy acceptance is required.
- [ ] Confirm birthday and gender save correctly.
- [ ] Log in with email/password.
- [ ] Confirm Settings shows standard sign-in.
- [ ] Confirm Mailbox Connection is visible.
- [ ] Confirm mailbox email/password fields are not visible when already connected.
- [ ] Click Change Email Connection and confirm the popup appears.
- [ ] Add mailbox credentials.
- [ ] Save mailbox connection.
- [ ] Confirm status changes to connected.
- [ ] Add one tracked contact.
- [ ] Run Summarizer.
- [ ] Confirm only emails from tracked contacts are summarized.
- [ ] Send a report by email if SMTP is configured.
- [ ] Export account data.
- [ ] Delete the account after testing, or keep it as a test account.

## 5. Scheduled Reports Test

Run this after Gmail or Microsoft is working.

- [ ] Open Scheduled Reports from the dashboard clock button.
- [ ] If no schedules exist, confirm it opens the New Schedule form.
- [ ] Create a schedule with a clear name.
- [ ] Confirm it immediately takes you to Saved Schedules.
- [ ] Confirm the schedule card shows name, active status, delivery method, cadence, timezone, recipient, days back, and next run.
- [ ] Use the plus button in Saved Schedules to create another schedule.
- [ ] Turn a schedule off.
- [ ] Turn it back on.
- [ ] Edit a schedule and save changes.
- [ ] Delete a schedule.
- [ ] Confirm the delete confirmation appears on top of the schedules modal.
- [ ] Confirm a scheduled report sends the same kind of full formatted report as a manual report.
- [ ] Confirm scheduled reports always run a fresh summarizer check first.
- [ ] Confirm scheduled reports do not duplicate unrelated contacts or other users' data.

## 6. Account Isolation And Privacy Test

Use two real accounts in two separate browsers or incognito windows.

- [ ] Account A adds contacts and generates summaries.
- [ ] Account A creates a schedule.
- [ ] Account A saves summary preferences.
- [ ] Account A toggles AI Attachment Access.
- [ ] Account A submits a bug report.
- [ ] Account B logs in.
- [ ] Account B cannot see Account A contacts.
- [ ] Account B cannot see Account A summaries.
- [ ] Account B cannot see Account A schedules.
- [ ] Account B cannot see Account A settings.
- [ ] Account B cannot see Account A bug reports.
- [ ] Account B cannot see Account A attachments.
- [ ] While logged into Account B, manually try a URL/API request using Account A's `user_id`.
- [ ] Confirm the app blocks cross-account access.
- [ ] Confirm the cross-account attempt appears in Admin Monitoring.

## 7. Data Retention And Deletion Test

- [ ] Open a summary and confirm it is marked read.
- [ ] Mark a summary done.
- [ ] Confirm read/done status persists after refresh.
- [ ] Confirm unread summaries are not purged.
- [ ] Confirm read/done summaries are eligible for source-body/attachment purge after the retention window.
- [ ] Confirm processed email IDs remain after purge so the same old email is not summarized again.
- [ ] Confirm deleting a summary manually removes the processed email ID so it can be rediscovered if scanned again.
- [ ] Delete an account and confirm contacts, summaries, email source records, attachments, schedules, analytics rows, and bug reports are removed.
- [ ] Export account data before deletion and confirm sensitive secrets are excluded.

## 8. Error Handling Test

- [ ] Try running summarizer with zero contacts and confirm the app says to add contacts first.
- [ ] Test an account missing Gmail read scope and confirm the message tells the user to reconnect with Google.
- [ ] Test an account missing Gmail/Microsoft send scope and confirm the message tells the user to reconnect for send permissions.
- [ ] Temporarily lower a usage limit in Render and confirm the app only shows the daily-limit message after the cap is actually hit.
- [ ] Confirm normal users do not see usage-limit language before hitting the cap.
- [ ] Confirm failed report delivery shows a clear message, not a raw stack trace.
- [ ] Confirm OAuth callback mismatch shows a clear login error.
- [ ] Confirm app errors appear in Admin Monitoring.

## 9. Admin, Monitoring, Analytics, And Bug Reports

- [ ] Confirm `/admin` opens in production.
- [ ] Confirm admin access works using admin email or admin key.
- [ ] Confirm Readiness panel loads.
- [ ] Confirm Analytics panel loads.
- [ ] Confirm Bug Reports panel loads.
- [ ] Confirm Monitoring panel loads.
- [ ] Trigger a harmless failed login.
- [ ] Confirm failed login/rate-limit events appear in Monitoring.
- [ ] Submit a bug report from Settings.
- [ ] Confirm it appears in Admin Bug Reports.
- [ ] Confirm analytics records:
  - signup conversion
  - first summary generated
  - contact added
  - scheduled report created
  - report delivered
  - summary opened
  - refinement used

## 10. Backup And Restore Test

Run the backup script on Render:

```bash
cd /opt/render/project/src/Email_Summarizer
python3 scripts/backup_persistent_data.py \
  --storage-dir /var/data/storage \
  --output-dir /var/data/output \
  --backup-dir /var/data/backups
```

- [ ] Confirm a backup archive is created.
- [ ] Download the archive off Render.
- [ ] Restore it into a separate local/test environment.
- [ ] Confirm restored login/profile data loads.
- [ ] Confirm restored contacts load.
- [ ] Confirm restored summaries load.
- [ ] Confirm restored schedules load.
- [ ] Confirm restored admin views load.
- [ ] Document where backups are stored and who can access them.

## 11. OAuth Verification Readiness

Already available in the app:

- [ ] Homepage exists at `/`.
- [ ] Privacy Policy exists at `/privacy`.
- [ ] Terms of Service exists at `/terms`.
- [ ] Security FAQ exists at `/security`.
- [ ] Public pages explain what data is read, stored, sent to AI, and deleted.
- [ ] README OAuth consent wording matches product behavior.

Google setup:

- [ ] Verify ownership of `discere-ai.com` in Google Search Console.
- [ ] Google app name is `Discere`.
- [ ] User support email is `discereresearch@gmail.com`.
- [ ] Homepage is `https://discere-ai.com/`.
- [ ] Privacy Policy is `https://discere-ai.com/privacy`.
- [ ] Terms of Service is `https://discere-ai.com/terms`.
- [ ] Authorized domain is `discere-ai.com`.
- [ ] Developer contact email is `discereresearch@gmail.com`.
- [ ] Google redirect URI is `https://discere-ai.com/auth/google/callback`.
- [ ] Requested scopes are:
  - `openid`
  - `email`
  - `profile`
  - `https://www.googleapis.com/auth/gmail.readonly`
  - `https://www.googleapis.com/auth/gmail.send`
- [ ] Google demo video shows homepage, login, consent screen, add contact, run summarizer, open summary, send report, Settings privacy controls, export, and delete account.

Microsoft setup:

- [ ] Azure app registration is under a Microsoft Entra work/school tenant.
- [ ] Publisher domain is `discere-ai.com`.
- [ ] Microsoft redirect URI is `https://discere-ai.com/auth/microsoft/callback`.
- [ ] Requested scopes are:
  - `openid`
  - `email`
  - `profile`
  - `offline_access`
  - `User.Read`
  - `Mail.Send`
  - `https://outlook.office.com/IMAP.AccessAsUser.All`
- [ ] If pursuing Microsoft publisher verification, confirm you have Partner Center / Microsoft AI Cloud Partner Program requirements ready.

## 12. Legal, Business, And Trust Checklist

- [ ] Decide whether launch is beta/early access or fully commercial.
- [ ] Decide whether to form an LLC before charging.
- [ ] If using `Discere Research` as the business name, confirm the Terms/Privacy reflect that accurately.
- [ ] Use the same business name across Terms, Privacy, Stripe, customer emails, and bank account.
- [ ] Get Terms reviewed by an attorney before broad commercial launch.
- [ ] Get Privacy Policy reviewed by an attorney before broad commercial launch.
- [ ] Confirm every privacy/security claim on the website is true in the actual product.
- [ ] Get a cyber liability insurance quote.
- [ ] Get a general/professional liability quote.
- [ ] Create a simple breach-response checklist.
- [ ] Avoid regulated customers first: healthcare, finance, legal, government, and large enterprise.

## 13. Stripe / Payment Checklist

Do this only when ready to charge.

- [ ] Create or finish Stripe account.
- [ ] Confirm the Stripe business/legal name matches the business name in Terms/Privacy.
- [ ] Create product: `Discere Early Access`.
- [ ] Create monthly price, suggested starting point: `$9/month`.
- [ ] Decide trial policy:
  - no-card trial for easier growth
  - card-required trial for cleaner conversion and less abuse
- [ ] Add Render env vars when payment code is added:
  - `STRIPE_SECRET_KEY`
  - `STRIPE_WEBHOOK_SECRET`
  - `STRIPE_PRICE_EARLY_ACCESS_MONTHLY`
  - optional `STRIPE_CUSTOMER_PORTAL_RETURN_URL`
- [ ] Add checkout-session endpoint.
- [ ] Add customer-portal endpoint.
- [ ] Add Stripe webhook endpoint.
- [ ] Store subscription state on the backend.
- [ ] Add plan-based limits.
- [ ] Update Terms with billing, cancellation, renewal, failed payment, refund, and trial language.
- [ ] Test checkout in Stripe test mode.
- [ ] Test cancellation in Stripe customer portal.
- [ ] Test failed payment behavior.
- [ ] Test webhook replay safety.
- [ ] Switch to live mode only after test mode works end-to-end.

## 14. Final Go / No-Go

Do not publicly launch until all critical items are checked:

- [ ] Gmail login works in production.
- [ ] Microsoft login works in production.
- [ ] Standard mailbox account flow works if you plan to support non-OAuth mailboxes at launch.
- [ ] Summarizer only processes tracked contacts.
- [ ] Account isolation is confirmed with two real accounts.
- [ ] Email report delivery works.
- [ ] Scheduled reports work.
- [ ] Export works.
- [ ] Delete account works.
- [ ] Backup and restore work.
- [ ] Admin monitoring works.
- [ ] OAuth consent screens match actual behavior.
- [ ] Terms/Privacy are ready for the launch type.
- [ ] Stripe is either intentionally not enabled, or fully tested if charging.
- [ ] You have a support email that customers can actually reach.
