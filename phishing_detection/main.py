# phishing_detection/main.py

from email_fetch import fetch_emails
from url_analysis import check_virustotal
from spf_validation import check_spf
from spelling_check import check_spelling
from geolocation import get_geolocation
from send_response import send_response
import re

def extract_sender_ip(headers):
    # Extract IP from Received header
    received_headers = headers.get_all('Received', [])
    for header in received_headers:
        # This regex pattern matches IP addresses in the "Received" headers
        match = re.search(r'\[([0-9.]+)\]', header)
        if match:
            return match.group(1)
    return None

def analyze_email(subject, sender, body, headers):
    # Perform URL Analysis
    print("Analyzing URLs...")
    urls = extract_urls(body)
    url_analysis_results = []
    for url in urls:
        result = check_virustotal(url)
        url_analysis_results.append(result)

    # Extract sender IP from email headers
    sender_ip = extract_sender_ip(headers)

    if sender_ip:
        # Perform SPF Validation
        print("Validating SPF...")
        sender_domain = extract_domain(sender)  # Extract domain from sender's email
        spf_result = check_spf(sender_ip, sender_domain)
    else:
        spf_result = "No IP address found in headers."

    # Perform Spelling Check
    print("Checking for spelling errors...")
    spelling_errors = check_spelling(body)

    # Perform GeoLocation Check
    print("Getting GeoLocation...")
    geo_location = get_geolocation(sender_ip) if sender_ip else "IP not found."

    # Compile Results
    analysis_result = f"Subject: {subject}\nSender: {sender}\n"
    analysis_result += f"SPF Result: {spf_result}\n"
    analysis_result += f"GeoLocation: {geo_location}\n"
    analysis_result += f"Spelling Errors: {spelling_errors}\n"
    analysis_result += f"URL Analysis: {url_analysis_results}\n"

    return analysis_result

def extract_urls(body):
    # Example function to extract URLs from the email body
    urls = re.findall(r'(https?://\S+)', body)
    return urls

def extract_domain(sender):
    # Extract the domain from the sender's email address
    return sender.split('@')[-1]

if __name__ == "__main__":
    # Fetch unread emails
    emails = fetch_emails()

    if not emails:
        print("No new emails found.")
    else:
        # Analyze each email
        for email_data in emails:
            subject = email_data['subject']
            sender = email_data['sender']
            body = email_data['body']
            headers = email_data['headers']  # Get headers

            # Perform analysis
            print(f"Analyzing email from {sender}...")
            result = analyze_email(subject, sender, body, headers)
            print(result)

            # Send the analysis report back to the sender
            send_response(sender, result)
