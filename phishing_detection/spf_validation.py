# phishing_detection/spf_validation.py
import spf

def check_spf(sender_ip, domain):
    result = spf.check2(i=sender_ip, s=domain, h='yourdomain.com')
    print(result)

if __name__ == "__main__":
    check_spf("1.2.3.4", "example.com")