import imaplib, email, email.utils, os
from dotenv import load_dotenv
load_dotenv()

mail = imaplib.IMAP4_SSL(os.getenv("IMAP_SERVER"), 993)
mail.login(os.getenv("IMAP_USER"), os.getenv("IMAP_PASSWORD"))
mail.select("INBOX")

# Search specifically for this sender, no date filter
_, data = mail.uid('SEARCH', None, 'FROM "ronnen.lovinger@dustphotonics.com"')
print("UIDs found:", data)

# Also try just ALL to see if anything comes back at all
_, data2 = mail.uid('SEARCH', None, 'ALL')
print("Total emails in INBOX:", len(data2[0].split()) if data2[0] else 0)

mail.logout()