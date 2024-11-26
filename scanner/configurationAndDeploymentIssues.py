import requests
import socket
import argparse

def check_ssrf(target_url):
    """
    Checks for SSRF vulnerabilities by attempting to access internal services.
    """
    payloads = [
        {"url": "http://127.0.0.1:80"},  # Access localhost
        {"url": "http://169.254.169.254"}  # Access AWS metadata service
    ]
    try:
        for payload in payloads:
            response = requests.post(target_url, json=payload, timeout=10)
            if response.status_code == 200 and "localhost" in response.text:
                print(f"[SSRF] Vulnerable to SSRF: {target_url}")
                return True
        return False
    except requests.RequestException as e:
        print(f"[SSRF] Unable to test {target_url}: {e}")
        return False

def check_insecure_dev_envs(target_url):
    """
    Checks for insecure development or test environment pages.
    """
    common_paths = [
        "/phpinfo.php",  # PHP info page
        "/test",         # Generic test page
        "/admin/dev",    # Development admin page
        "/debug",        # Debug endpoint
        "/staging"       # Staging environment
    ]
    
    try:
        for path in common_paths:
            response = requests.get(target_url + path, timeout=10)
            if response.status_code == 200 and "test" in response.text.lower():
                print(f"[Dev Envs] Insecure development environment found: {target_url + path}")
                return True
        return False
    except requests.RequestException as e:
        print(f"[Dev Envs] Unable to test {target_url}: {e}")
        return False

def check_subdomain_takeover(subdomain):
    """
    Checks if a subdomain is vulnerable to takeover by verifying DNS and HTTP responses.
    """
    try:
        ip = socket.gethostbyname(subdomain)
        response = requests.get(f"http://{subdomain}", timeout=10)
        if "no such host" in response.text.lower() or "error 404" in response.text.lower():
            print(f"[Subdomain] Potential subdomain takeover: {subdomain}")
            return True
        return False
    except socket.gaierror:
        print(f"[Subdomain] Subdomain does not resolve: {subdomain}")
        return False
    except requests.RequestException as e:
        print(f"[Subdomain] Unable to test {subdomain}: {e}")
        return False

