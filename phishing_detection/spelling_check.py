# phishing_detection/spelling_check.py
from spellchecker import SpellChecker

def check_spelling(body):
    spell = SpellChecker()
    words = body.split()
    misspelled = spell.unknown(words)

    for word in misspelled:
        print(f"Misspelled word: {word}")

if __name__ == "__main__":
    test_body = "Ths is a tst email with sum mistakes."
    check_spelling(test_body)
