# LEGAL STUFF DOCUMENT

This document is a practical launch-risk checklist for Discere. It is not legal advice and should be reviewed with a qualified attorney before commercial launch.

## What You Need To Prevent The Big Risks

The practical risk-reduction checklist is:

1. Form the LLC before charging customers.

Use the LLC name consistently in Terms, Privacy, Stripe, bank account, customer emails, and contracts. Keep separate bank accounts and accounting.

2. Get attorney review of Terms and Privacy.

Not because the pages need to be fancy, but because the wording must match actual product behavior. The FTC specifically warns that privacy promises must be honored, and companies still need appropriate security based on the data they hold.

3. Make every privacy/security claim provably true.

If the site says "we only read tracked contacts," the code and logs need to support that. If it says "delete account removes data," the deletion path needs to actually remove the relevant records/files.

4. Align OAuth consent screens exactly.

Google requires apps to accurately represent identity and intent. Microsoft publisher verification is about helping users/admins trust who publishes the app. Your consent copy should say: reads mailbox data to summarize emails from contacts users choose, sends email only for user-requested reports, uses profile/email for login, uses refresh/offline access for recurring scheduled reports.

5. Implement a breach response plan.

The FTC says breach response should include securing systems, fixing vulnerabilities, preserving evidence, involving legal/security help, and determining notification obligations. You do not need an enterprise SOC team on day one, but you do need a written incident checklist.

6. Buy insurance before business customers.

Look at cyber liability and general/professional liability. This is separate from an LLC. The LLC limits structural exposure; insurance helps pay defense/response costs.

7. Avoid regulated-data customers at first.

Do not market to healthcare, finance, legal, government, or highly regulated enterprise until you have stronger compliance, contracts, audit logs, vendor reviews, and maybe SOC 2.

8. Keep the product scope narrow.

"Summaries for emails from important contacts" is safer than "AI knows everything in your inbox." Narrow promises are easier to honor.

## Does An LLC Fix The Personal Asset Risk?

It helps a lot with normal business liability, but it is not a shield against everything.

Best setup:

- LLC formed and active.
- Business bank account.
- No mixing personal/business funds.
- Contracts and Terms are under the LLC.
- Insurance in LLC name.
- Accurate privacy/security claims.
- Clean logs of consent, deletion, and account actions.
- No personal guarantees if avoidable.

Without those, the LLC is weaker.

## What To Do Before Commercial Launch

Minimum before paid users:

- Form LLC or decide intentionally to operate as sole proprietor for beta only.
- Attorney review of Terms/Privacy.
- Add payment terms once Stripe/pricing exists.
- Finalize OAuth consent wording.
- Confirm account deletion/export works.
- Confirm backup/restore works.
- Confirm account isolation with two real accounts.
- Add breach response checklist.
- Get cyber liability quote.
- Keep first users as beta users with clear "early access" language.

For Discere, forming an LLC before charging businesses is the safer path. But the LLC is only one piece. The bigger issue is: do not promise privacy/security behavior unless the app actually does it.
