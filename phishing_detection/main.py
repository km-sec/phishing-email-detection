# phishing_detection/main.py

from email_fetch import fetch_emails
from url_analysis import check_virustotal
from spf_validation import check_spf
from spelling_check import check_spelling  # Updated for TextGears integration
from geolocation import get_geolocation
from send_response import send_response
import re

def extract_sender_ip(headers):
    # This function looks through the 'Received' email headers to find the sender's IP address.
    received_headers = headers.get_all('Received', [])
    for header in received_headers:
        # This regex matches both IPv4 and IPv6 addresses
        match = re.search(r'\[([0-9a-fA-F:.]+)\]', header)
        if match:
            return match.group(1)  # Return the first matched IP address found.
    return None

def analyze_email(subject, sender, body, headers):
    # Step 1: Analyze URLs found in the email body using VirusTotal.
    print("Analyzing URLs...")
    urls = extract_urls(body)  # Extract URLs from the email body.
    url_analysis_results = []
    
    if urls:
        for url in urls:
            result = check_virustotal(url)  # Check each URL against VirusTotal.
            url_analysis_results.append(f"URL: {result['url']} - Status: {result['status']} - Engines Checked: {result['total_engines_checked']}")
    else:
        url_analysis_results.append("No URLs found in the email body.")

    # Step 2: Extract the sender's IP address for SPF validation and GeoLocation.
    sender_ip = extract_sender_ip(headers)

    if sender_ip:
        # If we have the sender's IP, we can move on to SPF validation.
        print("Validating SPF...")
        sender_domain = extract_domain(sender)  # Get the domain from the sender's email address.
        spf_result = check_spf(sender_ip, sender_domain)  # Validate the email's SPF record.

    else:
        spf_result = "No IP address found in headers."  # Handle cases where no IP is available.

    # Step 3: Check both the subject and body for spelling mistakes using TextGears API.
    print("Checking for spelling errors...")
    spelling_errors = check_spelling(subject + " " + body)  # Updated with TextGears API function.

    # Step 4: Determine the sender's location based on the extracted IP address.
    print("Getting GeoLocation...")
    geo_location = get_geolocation(sender_ip) if sender_ip else "IP not found."  # Get location based on the sender's IP.

    # Step 5: Compile all the analysis results into a report that will be sent back to the user.
    analysis_result = f"Subject: {subject}\n"
    analysis_result += f"Sender: {extract_email(sender)}"
    analysis_result += f"\n"
    analysis_result += f"SPF Result: {spf_result}\n"
    analysis_result += f"GeoLocation: {geo_location}\n"

    # Handle spelling errors more clearly.
    if spelling_errors:
        analysis_result += f"Spelling Errors: {', '.join(spelling_errors)}\n"
    else:
        analysis_result += "Spelling Errors: None\n"

    analysis_result += "URL Analysis:\n" + "\n".join(url_analysis_results) + "\n"

    return analysis_result  # Return the full analysis report.

def extract_urls(body):
    # This function extracts URLs from the email body. It uses regex to find patterns that look like URLs (starting with http or https).
    urls = re.findall(r'(https?://\S+)', body)  # Find all URL patterns in the body.
    return urls  # Return the list of URLs.

def extract_domain(sender):
    # This function extracts the domain from the sender's email address.
    domain = sender.split('@')[-1].strip()  # Strip any extra spaces or characters
    if '>' in domain:  # Handle cases where '>' might be included
        domain = domain.replace('>', '')  # Remove '>' from the domain
    return domain

def extract_email(sender):
    # Use regex to extract the email address between '<' and '>'
    match = re.search(r'<(.*?)>', sender)
    if match:
        return match.group(1)  # Return the email address
    else:
        return sender  # If no match, return the input (might already be an email)

if __name__ == "__main__":
    # Fetch unread emails from the user's inbox.
    emails = fetch_emails()

    if not emails:
        print("No new emails found.")  # If no emails are available, notify the user.
    else:
        # Analyze each fetched email one by one.
        for email_data in emails:
            subject = email_data['subject']  # Extract the subject of the email.
            sender = email_data['sender']  # Extract the sender's email address.
            body = email_data['body']  # Extract the body content of the email.
            headers = email_data['headers']  # Extract the email headers for further analysis.

            # Perform a full analysis of the email.
            print(f"Analyzing email from {sender}...")
            result = analyze_email(subject, sender, body, headers)
            print(result)

            # Send the analysis report back to the user.
            send_response(sender, result)
