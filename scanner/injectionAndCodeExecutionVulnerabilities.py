import requests
import json

def check_ssti(target_url):
    """
    Scans the target URL for Server-Side Template Injection (SSTI) vulnerabilities.

    Parameters:
    - target_url (str): The URL of the target website (POST endpoint).

    Returns:
    - bool: Returns True if SSTI vulnerability is detected, otherwise False.
    """
    if not isinstance(target_url, str):
        raise ValueError("The target URL must be a string")

    # Payloads for testing SSTI in various template engines
    payloads = [
        "{{7*7}}",  # Common for Jinja2, Django, and similar engines
        "${7*7}",   # Common for Spring and similar engines
    ]

    # Loop over the payloads and send requests
    for payload in payloads:
        try:
            # Sending the payload as form data in a POST request
            response = requests.post(target_url, data={"input": payload}, timeout=10)

            # Check if the response contains the result of the SSTI payload
            if "49" in response.text:  # 7 * 7 = 49
                print(f"SSTI vulnerability detected with payload: {payload}")
                return True
        
        except requests.RequestException as e:
            print(f"Request error: {e}")
            continue  # Proceed with the next payload in case of a request error

    # Return False if no SSTI vulnerability is detected
    return False



def check_js_prototype_pollution(target_url):
    """
    Scans the target URL for JavaScript Prototype Pollution vulnerabilities.

    Parameters:
    - target_url (str): The URL of the target website (POST endpoint).

    Returns:
    - bool: Returns True if JavaScript Prototype Pollution is detected, otherwise False.
    """
    if not isinstance(target_url, str):
        raise ValueError("The target URL must be a string")

    # Payload for prototype pollution
    payload = {
        "__proto__": {
            "polluted": "true"
        }
    }
    
    headers = {"Content-Type": "application/json"}
    
    try:
        # Send POST request with prototype pollution payload
        response = requests.post(target_url, data=json.dumps(payload), headers=headers, timeout=10)
        
        # Check if the response reflects the polluted property
        if "polluted" in response.text:
            print("Prototype Pollution vulnerability detected.")
            return True
        return False

    except requests.RequestException as e:
        print(f"Error during request: {e}")
        return False


def check_host_header_injection(target_url):
    """
    Checks if a website is vulnerable to Host Header Injection by sending a request with a manipulated Host header.

    Parameters:
    - target_url (str): The URL of the target website (GET endpoint).

    Returns:
    - bool: Returns True if Host Header Injection is detected, otherwise False.
    """
    if not isinstance(target_url, str):
        raise ValueError("The target URL must be a string")

    malicious_host = "malicious.example.com"
    headers = {
        "Host": malicious_host
    }
    
    try:
        # Send GET request with manipulated Host header
        response = requests.get(target_url, headers=headers, timeout=10)
        
        # Check if the malicious host is reflected in the response
        if malicious_host in response.text:
            print("Host Header Injection vulnerability detected.")
            return True
        return False

    except requests.RequestException as e:
        print(f"Error during request: {e}")
        return False