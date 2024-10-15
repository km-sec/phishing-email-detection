# phishing_detection/url_analysis.py
import requests
import base64
from config.config import VIRUSTOTAL_API_KEY  # Import the API key from the config file
import re

def check_virustotal(url):
    # Encode the URL for the VirusTotal API request
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Use the API key from the config file
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY  
    }
    
    # Request to VirusTotal API to check the URL
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    data = response.json()
    
    # Extract analysis results
    analysis_results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    
    # Count the number of engines and results
    harmless_count = 0
    malicious_count = 0
    engine_count = 0
    
    for engine, result in analysis_results.items():
        engine_count += 1
        if result.get("category") == "harmless":
            harmless_count += 1
        elif result.get("category") == "malicious":
            malicious_count += 1
    
    # Determine if the URL passes or fails based on whether any engine flagged it as malicious
    if malicious_count > 0:
        url_status = "Fail"
    else:
        url_status = "Pass"
    
    return {
        "url": truncate_url(url),
        "status": url_status,
        "total_engines_checked": engine_count
    }

# Function to truncate URLs and add three periods
def truncate_url(url):
    # Remove 'https://', 'http://', and 'www.'
    url = re.sub(r'^https?://(www\.)?', '', url)
    
    # Truncate anything after '?', usually tracking or unnecessary parameters
    truncated = url.split('?')[0]
    
    # Add three periods at the end to indicate truncation
    return truncated + "..."

if __name__ == "__main__":
    test_urls = ["https://www.cnn.com/world", "https://www.gmanetwork.com/news/"]
    
    for url in test_urls:
        result = check_virustotal(url)
        print(f"URL: {result['url']}")
        print(f"Status: {result['status']}")
        print(f"Number of engines checked: {result['total_engines_checked']}\n")