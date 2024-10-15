import schedule
import time
from phishing_detection.main import analyze_email
from email_fetch import fetch_emails

def job():
    # Fetch unread emails from the user's inbox.
    emails = fetch_emails()

    if not emails:
        print("No new emails found.")
    else:
        # Analyze each fetched email one by one.
        for email_data in emails:
            subject = email_data['subject']
            sender = email_data['sender']
            body = email_data['body']
            headers = email_data['headers']

            # Perform a full analysis of the email.
            result = analyze_email(subject, sender, body, headers)
            print(result)

# Schedule the job to run every 10 minutes
schedule.every(10).minutes.do(job)

while True:
    schedule.run_pending()
    time.sleep(1)
