# phishing_detection/spf_validation.py
import spf

def check_spf(sender_ip, domain):
    # Perform SPF check and handle cases with two or three return values
    spf_response = spf.check2(i=sender_ip, s=domain, h='gmail.com')
    
    if len(spf_response) == 3:
        result, modifier, explanation = spf_response
    else:
        result, explanation = spf_response
        modifier = ''  # Set modifier to an empty string if not returned

    # Create a detailed SPF result message based on the outcome
    if result == 'pass':
        spf_result = "Pass: The sender's IP is authorized to send emails for this domain."
    elif result == 'fail':
        spf_result = f"Fail: The sender's IP is NOT authorized to send emails for this domain. {explanation}"
    elif result == 'softfail':
        spf_result = f"SoftFail: The sender's IP is probably not authorized, but the domain suggests caution. {explanation}"
    elif result == 'neutral':
        spf_result = f"Neutral: The domain does not specify if the sender's IP is authorized. {explanation}"
    elif result == 'none':
        spf_result = f"None: No SPF record found for the domain. {explanation}"
    elif result == 'temperror':
        spf_result = f"TempError: A temporary error occurred during the SPF check (e.g., DNS issue). {explanation}"
    elif result == 'permerror':
        spf_result = f"PermError: A permanent error occurred (e.g., misconfigured SPF record). {explanation}"
    else:
        spf_result = "SPF Unknown: An unknown SPF result was returned."

    print(f"SPF Check Result: {spf_result}")
    
    return spf_result  # Return the detailed SPF result message

if __name__ == "__main__":
    check_spf("1.2.3.4", "example.com")
