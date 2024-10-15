# phishing_detection/geolocation.py
# Using ipinfo.io API to request for the geolocation  
import requests

def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            # Check if location data is available
            if 'city' in data and 'region' in data and 'country' in data:
                return f"Location: {data['city']}, {data['region']}, {data['country']}"
            else:
                return "Geolocation information not found."
        else:
            return f"Error: Unable to fetch data, received status code {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: Failed to fetch geolocation due to {e}"

if __name__ == "__main__":
    print(get_geolocation("8.8.8.8"))
