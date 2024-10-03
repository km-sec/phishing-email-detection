# phishing_detection/send_response.py
import smtplib
from email.mime.text import MIMEText

def send_response(to_email, body):
    smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    smtp.login("phishchecker.ca@gmail.com", "jzso pvkq jiwa dpaf")

    msg = MIMEText(body)
    msg['Subject'] = 'Phishing Analysis Result'
    msg['From'] = "phishchecker.ca@gmail.com"
    msg['To'] = to_email

    smtp.sendmail("phishchecker.ca@gmail.com", to_email, msg.as_string())
    smtp.quit()

if __name__ == "__main__":
    send_response("recipient@example.com", "This is the phishing analysis result.")
