# phishing_detection/email_fetch.py
# this is for getting the email and looping thru them.
import imaplib
import email
from email.header import decode_header
from config.config import EMAIL_ADDRESS, EMAIL_PASSWORD, IMAP_SERVER, IMAP_PORT

def fetch_emails():
    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    imap.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    imap.select("inbox")

    status, messages = imap.search(None, 'UNSEEN')
    
    if status != 'OK':
        return []

    email_list = []
    
    for num in messages[0].split():
        status, msg_data = imap.fetch(num, "(RFC822)")
        if status != 'OK':
            continue

        msg = email.message_from_bytes(msg_data[0][1])

        subject = decode_header(msg["Subject"])[0][0]
        sender = msg.get("From")

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode()
        else:
            body = msg.get_payload(decode=True).decode()

        # Getting the entire email headers for IP extraction
        headers = msg

        email_list.append({
            'subject': subject,
            'sender': sender,
            'body': body,
            'headers': headers  
        })

    imap.logout()
    return email_list
