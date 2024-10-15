import requests

# Your TextGears API key
API_KEY = 'XHffqyk07ZNWCwLF'

def check_spelling(text):
    # Send a request to the TextGears API
    response = requests.get(
        "https://api.textgears.com/spelling",
        params={
            'text': text,
            'key': API_KEY
        }
    )

    # Parse the JSON response from the API
    result = response.json()

    # Collect all misspelled words from the response
    misspelled_words = []
    if result['status']:
        for error in result['response']['errors']:
            misspelled_words.append(error['bad'])  # Collect the misspelled word

    return misspelled_words

if __name__ == "__main__":
    # Example usage
    test_text = "This is a testng email for text gears"
    misspelled = check_spelling(test_text)
    print("Misspelled words:", misspelled)
