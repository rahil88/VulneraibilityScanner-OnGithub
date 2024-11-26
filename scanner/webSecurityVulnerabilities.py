import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import requests
import sys

def check_html5_storage(target_url):
    """
    Checks if sensitive data (password, token, secret, etc.) is stored in localStorage or sessionStorage
    on the target URL using a headless browser.
    
    Args:
        target_url (str): The URL of the server to test.
        
    Returns:
        bool: True if sensitive data is found in storage, False otherwise.
    """
    try:
        # Set up headless browser for testing
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")  # Disable GPU for better CI/CD compatibility
        options.add_argument("--no-sandbox")  # Essential for CI/CD environments like GitHub Actions
        driver = webdriver.Chrome(options=options)

        driver.get(target_url)

        # Execute JavaScript to check for sensitive data in storage
        local_storage_data = driver.execute_script("return JSON.stringify(localStorage);")
        session_storage_data = driver.execute_script("return JSON.stringify(sessionStorage);")

        driver.quit()

        # Check if sensitive data is present (e.g., passwords, tokens, etc.)
        sensitive_keywords = ["password", "token", "secret", "key"]
        for keyword in sensitive_keywords:
            if keyword in local_storage_data or keyword in session_storage_data:
                logging.error(f"Sensitive data found in storage for {target_url}.")
                return True  # Vulnerable

        logging.info(f"No sensitive data found in storage for {target_url}.")
        return False  # Not Vulnerable

    except WebDriverException as e:
        logging.error(f"WebDriver error while testing {target_url}: {e}")
        return False  # Unable to test
    except Exception as e:
        logging.error(f"Error while testing {target_url}: {e}")
        return False  # Unable to test


def check_csp(target_url):
    """
    Checks if the target URL has a secure Content Security Policy (CSP).
    Returns True if vulnerable (no CSP or unsafe CSP directives), False otherwise.

    Args:
        target_url (str): The URL of the server to test.

    Returns:
        bool: True if the site is vulnerable (no CSP or unsafe CSP directives), False otherwise.
    """
    try:
        response = requests.get(target_url, timeout=10)
        headers = response.headers

        # Get the Content-Security-Policy header
        csp = headers.get('Content-Security-Policy')
        if not csp:
            print(f"Vulnerable to CSP issues: No CSP header found on {target_url}", file=sys.stderr)
            return True  # Vulnerable (No CSP header)

        # Basic unsafe CSP patterns
        unsafe_directives = [
            "unsafe-inline",
            "unsafe-eval",
            "*",  # Allowing all origins
            "data:",  # Permitting data URIs
            "blob:"  # Permitting blob URIs
        ]

        # Check for unsafe directives in the CSP
        for directive in unsafe_directives:
            if directive in csp:
                print(f"Vulnerable to CSP issues: Unsafe directive found in CSP on {target_url}", file=sys.stderr)
                return True  # Vulnerable CSP

        print(f"Secure CSP found on {target_url}", file=sys.stderr)
        return False  # Secure CSP

    except requests.RequestException as e:
        print(f"Error checking CSP for {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test
    

def check_clickjacking(target_url):
    """
    Checks if the target URL is vulnerable to clickjacking by examining the HTTP headers.
    The vulnerability is indicated if the 'X-Frame-Options' and 'Content-Security-Policy' headers are missing.

    Args:
        target_url (str): The URL of the server to test.

    Returns:
        bool: True if the target is vulnerable to clickjacking, False otherwise.
    """
    try:
        response = requests.get(target_url, timeout=10)
        headers = response.headers

        # Check if headers are missing that would prevent clickjacking
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            print(f"Vulnerable to Clickjacking: {target_url}", file=sys.stderr)
            return True  # Vulnerable
        else:
            print(f"Not Vulnerable to Clickjacking: {target_url}", file=sys.stderr)
            return False  # Not Vulnerable

    except requests.RequestException as e:
        print(f"Error testing Clickjacking vulnerability on {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test