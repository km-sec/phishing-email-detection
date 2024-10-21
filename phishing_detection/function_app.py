# phishing_detection/function_app.py
import logging
import azure.functions as func
from phishing_detection.main import analyze_email
from phishing_detection.email_fetch import fetch_emails  # Correct import

app = func.FunctionApp()

@app.timer_trigger(schedule="0 */10 * * * *", arg_name="myTimer", run_on_startup=False, use_monitor=False)
def timer_trigger1(myTimer: func.TimerRequest) -> None:
    logging.info('Python timer trigger function executed.')
    
    # Call the email analysis function
    emails = fetch_emails()  # Assuming fetch_emails is already in your phishing_detection package
    if emails:
        for email in emails:
            result = analyze_email(email['subject'], email['sender'], email['body'], email['headers'])
            logging.info(f"Analysis Result: {result}")
    else:
        logging.info("No new emails to analyze.")
