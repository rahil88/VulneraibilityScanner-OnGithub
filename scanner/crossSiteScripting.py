import requests
import argparse

def is_xss_vulnerable(url):
    """
    Checks if a URL is vulnerable to Cross-Site Scripting (XSS) attacks.
    
    Args:
        url (str): The target URL to test for XSS vulnerabilities.
        
    Returns:
        bool: True if the URL is vulnerable to XSS, False otherwise.
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><svg onload=alert('XSS')>"
    ]

    try:
        for payload in xss_payloads:
            # Send the payload as a query parameter
            response = requests.get(f"{url}?input={payload}", timeout=10)
            if payload in response.text:
                print(f"[XSS] Vulnerability detected with payload: {payload}")
                return True
        print("[XSS] No vulnerabilities detected.")
        return False
    except requests.RequestException as e:
        print(f"[XSS] Error testing {url}: {e}")
        return False
