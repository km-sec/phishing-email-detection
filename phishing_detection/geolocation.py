# phishing_detection/geolocation.py
import requests

def get_geolocation(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    print(f"Location: {data['city']}, {data['region']}, {data['country']}")

if __name__ == "__main__":
    get_geolocation("8.8.8.8")
