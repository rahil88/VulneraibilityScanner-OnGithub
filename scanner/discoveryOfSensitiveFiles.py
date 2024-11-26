import requests
import re
import argparse


def is_weak_password_policy(url):
    """
    Checks if the application has a weak password policy by testing common weak passwords.
    
    Args:
        url (str): The target URL to test login functionality.
        
    Returns:
        bool: True if weak passwords are allowed, False otherwise.
    """
    weak_passwords = [
        "password123", "admin123", "123456", "qwerty", "letmein", "welcome", "iloveyou", "123qwe"
    ]
    dictionary_passwords = ["123456", "password", "123123", "admin", "12345", "letmein", "qwerty", "password1"]

    vulnerable = False
    for password in weak_passwords + dictionary_passwords:
        data = {'username': 'testuser', 'password': password}
        try:
            response = requests.post(url + "/login", data=data, timeout=10)
            if response.status_code == 200 and ("Welcome" in response.text or "Dashboard" in response.text):
                print(f"[Weak Password Policy] Weak password '{password}' bypassed login.")
                vulnerable = True
        except requests.RequestException as e:
            print(f"[Weak Password Policy] Error while testing password '{password}': {e}")
            continue

    return vulnerable


def has_hardcoded_credentials(url):
    """
    Scans the web page for hardcoded credentials in source code or configuration files.
    
    Args:
        url (str): The target URL to scan.
        
    Returns:
        bool: True if hardcoded credentials are found, False otherwise.
    """
    try:
        response = requests.get(url, timeout=10)
        credentials_pattern = re.compile(r"(username|user|email|password|passwd|pass)[:=\s]+[\"'].*[\"']")
        
        if credentials_pattern.search(response.text):
            print("[Hardcoded Credentials] Hardcoded credentials found in source code.")
            return True
    except requests.RequestException as e:
        print(f"[Hardcoded Credentials] Error while accessing URL: {e}")
    return False


def is_insecure_storage_used(url):
    """
    Checks if sensitive data like passwords or tokens are stored insecurely (e.g., in localStorage/sessionStorage).
    
    Args:
        url (str): The target URL to scan.
        
    Returns:
        bool: True if insecure storage is detected, False otherwise.
    """
    try:
        response = requests.get(url, timeout=10)
        insecure_storage_patterns = [
            re.compile(r"localStorage\.setItem\(.*password.*\)"),
            re.compile(r"sessionStorage\.setItem\(.*token.*\)")
        ]
        
        for pattern in insecure_storage_patterns:
            if pattern.search(response.text):
                print("[Insecure Storage] Sensitive data stored insecurely.")
                return True
    except requests.RequestException as e:
        print(f"[Insecure Storage] Error while accessing URL: {e}")
    return False


def is_unencrypted_data_transmitted(url):
    """
    Checks if the website uses unencrypted (non-HTTPS) data transmission.
    
    Args:
        url (str): The target URL to check.
        
    Returns:
        bool: True if unencrypted transmission is detected, False otherwise.
    """
    if url.startswith("http://"):
        print("[Unencrypted Data] Website uses unencrypted HTTP.")
        return True
    print("[Unencrypted Data] Website uses HTTPS.")
    return False


def has_insufficient_logging(url):
    """
    Checks if the application lacks sufficient logging by looking for a /logs endpoint.
    
    Args:
        url (str): The target URL to test for logging endpoints.
        
    Returns:
        bool: True if insufficient logging is detected, False otherwise.
    """
    try:
        response = requests.get(url + "/logs", timeout=10)
        if response.status_code == 200 and "log" in response.text.lower():
            print("[Insufficient Logging] Logs are accessible publicly.")
            return False  # Logs exist, and this is bad for security.
    except requests.RequestException:
        print("[Insufficient Logging] Logging endpoint is not accessible.")
    return True  # Logs are insufficient or not exposed.


def logs_sensitive_data(url):
    """
    Checks if sensitive data (e.g., passwords, credit cards) are logged in responses.
    
    Args:
        url (str): The target URL to scan for sensitive data in logs.
        
    Returns:
        bool: True if sensitive data is logged, False otherwise.
    """
    sensitive_keywords = ["password", "credit card", "ssn"]
    try:
        response = requests.get(url, timeout=10)
        for keyword in sensitive_keywords:
            if keyword in response.text.lower():
                print(f"[Sensitive Data Logging] Sensitive data '{keyword}' found in logs.")
                return True
    except requests.RequestException as e:
        print(f"[Sensitive Data Logging] Error while accessing URL: {e}")
    return False


