# phishing_detection/url_analysis.py
import requests
import base64
from config.config import VIRUSTOTAL_API_KEY  # Import the API key from the config file

def check_virustotal(url):
    # Encode the URL in base64 format for the VirusTotal API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY  # Use the API key from the config
    }
    
    # Make a request to the VirusTotal API to check the URL
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    
    # Return the result of the URL analysis
    return response.json()

if __name__ == "__main__":
    test_url = "https://www.cnn.com/world"
    result = check_virustotal(test_url)
    print(result)
