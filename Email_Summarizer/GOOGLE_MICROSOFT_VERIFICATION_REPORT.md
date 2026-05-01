# Google and Microsoft Verification Readiness Report

Last updated: May 1, 2026

This report separates what has been handled in the Discere codebase from what still needs to be completed in Google Cloud, Microsoft Entra, Render, DNS, and live testing.

## What was handled in the app

- Discere public pages now state more clearly that tracked contacts are not notified when they are added or summarized.
- The public Security FAQ now describes manual mailbox support as a private-client path, not part of the normal Gmail/Microsoft public product.
- Google and Microsoft setup failures now use support-oriented user-facing messages instead of telling users about OAuth client IDs, secrets, or redirect URLs.
- Existing code requests Gmail read-only access for Google and does not request Gmail send/modify/delete scopes.
- Existing code requests Microsoft `Mail.Read`, `offline_access`, `openid`, `email`, and `profile`, and does not request Microsoft `Mail.Send` or `Mail.ReadWrite`.
- Existing report email behavior is designed to send reports from Discere's report sender to the user's connected account email, not from the user's Gmail or Microsoft mailbox.
- Existing tests cover account isolation, token redaction, Microsoft reconnect errors, report recipient behavior, and sanitized summarizer failures.

## What Ben needs to do in Render

Confirm these production environment variables are set on the live Render service:

```text
EMAIL_SUMMARIZER_PUBLIC_BASE_URL=https://discere-ai.com
EMAIL_SUMMARIZER_STORAGE_DIR=/var/data/storage/app
EMAIL_SUMMARIZER_COOKIE_SECURE=true
EMAIL_SUMMARIZER_ENCRYPTION_KEY=<stable strong secret>
EMAIL_SUMMARIZER_ADMIN_KEY=<stable strong secret>
OPENAI_API_KEY=<production OpenAI API key>

GOOGLE_CLIENT_ID=<production Google OAuth client ID>
GOOGLE_CLIENT_SECRET=<production Google OAuth client secret>
GOOGLE_REDIRECT_URI=https://discere-ai.com/auth/google/callback

MICROSOFT_CLIENT_ID=<production Microsoft app client ID>
MICROSOFT_CLIENT_SECRET=<production Microsoft client secret>
MICROSOFT_TENANT_ID=common
MICROSOFT_REDIRECT_URI=https://discere-ai.com/auth/microsoft/callback

EMAIL_SUMMARIZER_REPORT_SMTP_HOST=<report sender SMTP host>
EMAIL_SUMMARIZER_REPORT_SMTP_PORT=<465 or 587>
EMAIL_SUMMARIZER_REPORT_SMTP_USER=<report sender username>
EMAIL_SUMMARIZER_REPORT_SMTP_PASSWORD=<report sender password or API key>
EMAIL_SUMMARIZER_REPORT_FROM_EMAIL=<Discere sender address>
EMAIL_SUMMARIZER_REPORT_FROM_NAME=Discere
```

If the private manual/VIP client path is enabled, also set:

```text
EMAIL_SUMMARIZER_MANUAL_MAILBOX_ALLOWED_EMAILS=<approved VIP email>
EMAIL_SUMMARIZER_MANUAL_SIGNUP_ACCESS_PASSWORD=<private invite password>
EMAIL_SUMMARIZER_VIP_MAILBOX_EMAIL=<approved VIP email>
EMAIL_SUMMARIZER_VIP_MAILBOX_PASSWORD=<VIP 263 client authorization code or app password>
```

Do not put secrets in GitHub, screenshots, chat messages, docs, or frontend JavaScript.

## What Ben needs to do in Google Cloud

- Use the production Google Cloud project, not a temporary dev project.
- Set app name to `Discere`.
- Add authorized domain: `discere-ai.com`.
- Set homepage: `https://discere-ai.com/`.
- Set privacy policy: `https://discere-ai.com/privacy`.
- Set terms of service: `https://discere-ai.com/terms`.
- Set authorized redirect URI exactly: `https://discere-ai.com/auth/google/callback`.
- Request only the Gmail scope Discere needs: `https://www.googleapis.com/auth/gmail.readonly`.
- Do not request Gmail send, modify, compose, or delete scopes.
- Use a working support email and developer contact email.
- Upload the Discere logo used on the public site.
- Prepare an unlisted demo video showing Google login, consent, adding a tracked contact, running the summarizer, opening a summary, Settings privacy controls, and account deletion location.

## What Ben needs to do in Microsoft Entra

- Use the production Microsoft Entra app registration.
- Set app name to `Discere`.
- Configure platform type `Web`.
- Set redirect URI exactly: `https://discere-ai.com/auth/microsoft/callback`.
- Choose supported account types intentionally:
  - Use `Accounts in any organizational directory and personal Microsoft accounts` if public Outlook.com, Hotmail, and Microsoft 365 users should all be supported.
  - Use personal Microsoft accounts only if Discere should support consumer Outlook/Hotmail accounts but not work/school tenants.
  - Use organizational accounts only if Discere should support Microsoft 365 work/school tenants only.
- Add only delegated permissions needed by Discere:
  - `openid`
  - `email`
  - `profile`
  - `offline_access`
  - `Mail.Read`
- Do not add `Mail.Send`, `Mail.ReadWrite`, application mailbox permissions, or admin-only permissions unless the product changes.
- Configure app branding, logo, homepage URL, privacy URL, terms URL, and support contact.
- Verify the publisher/domain if Microsoft allows it for the account.
- Test with both a personal Outlook account and, if relevant, a Microsoft 365 work/school account.

## Live smoke test checklist

Run these checks on `https://discere-ai.com`, not localhost.

1. Open the homepage, Privacy Policy, Terms, Security FAQ, and How-To pages in a normal browser.
2. Log in with Google and confirm the consent screen shows Discere and Gmail read-only access.
3. Add one tracked Gmail contact.
4. Run the summarizer and confirm it does not run with no contacts.
5. Open a generated summary and confirm no Markdown artifacts or raw errors appear.
6. Send a report email and confirm it goes to the logged-in user's connected email only.
7. Log out and log back in with Google; confirm the account is not treated as new unless it was deleted.
8. Repeat login, contact add, summarizer run, and summary open with Microsoft.
9. Revoke Google access from Google Account permissions and confirm Discere shows a clean reconnect message.
10. Revoke Microsoft access from Microsoft consent management or My Apps and confirm Discere shows a clean reconnect message.
11. Delete a test account from Settings and confirm the user cannot access dashboard data afterward.
12. Check `/health/readiness` and confirm `cookie_secure` is true and there are no critical errors.

## Remaining concerns

- Google and Microsoft review decisions depend on the live OAuth consent screens and provider-side app configuration, not just the code.
- Work/school Microsoft tenants can block user consent even when Discere requests only delegated `Mail.Read`; some organizations may require admin approval.
- Deliverability for report emails still depends on the report sender domain/provider. For production, use a domain-authenticated transactional sender such as Postmark or Resend instead of a generic Gmail SMTP account.
- The legal pages are stronger drafts but should still be reviewed by an attorney before broad paid launch.
- The public manual/VIP flow should stay hidden and allowlisted. Do not give normal users raw mailbox-password setup.
