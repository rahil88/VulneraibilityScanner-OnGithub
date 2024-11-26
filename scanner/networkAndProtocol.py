import requests
import socket
from urllib.parse import urlparse
import ipaddress
import ssl


def check_ip_spoofing(url):
    """
    Checks if the application is vulnerable to IP Spoofing by attempting to 
    spoof the 'X-Forwarded-For' header with known IP addresses.
    
    Args:
        url (str): The URL of the target service to check.
    
    Returns:
        bool: True if the domain is vulnerable to IP Spoofing, otherwise False.
    """
    spoofed_ips = [
        "192.168.1.100",  # Example private IP
        "10.0.0.1",       # Private IP
        "172.16.0.1",      # Private IP
        "8.8.8.8",         # Public IP (Google DNS)
        "127.0.0.1",       # Localhost
    ]
    
    try:
        for spoofed_ip in spoofed_ips:
            headers = {"X-Forwarded-For": spoofed_ip}
            response = requests.get(url, headers=headers, timeout=10)
            
            # Check if the spoofed IP appears in the response or if the behavior is abnormal
            if response.status_code == 200 and spoofed_ip in response.text:
                print(f"IP Spoofing detected with IP: {spoofed_ip}")
                return True  # Vulnerable to IP spoofing
        
        print("No IP spoofing vulnerability detected.")
        return False  # No spoofing vulnerability detected
    except requests.RequestException as e:
        print(f"Error during request: {e}")
        return False  # Unable to test
    


def check_dns_rebinding(url):
    """
    Checks if a domain is vulnerable to DNS Rebinding by resolving its IP addresses
    and checking if any resolved IP falls within private IP address ranges.
    
    Args:
        url (str): The URL of the target service to check.

    Returns:
        bool: True if the domain is vulnerable to DNS rebinding, otherwise False.
    """
    # Parse the URL to get the domain name
    parsed_url = urlparse(url)
    domain = parsed_url.hostname

    private_ip_ranges = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16")
    ]

    try:
        # Resolve the domain to its IP addresses
        resolved_ips = socket.gethostbyname_ex(domain)[2]

        for ip in resolved_ips:
            ip_obj = ipaddress.IPv4Address(ip)

            # Check if the IP is within any private IP ranges
            for private_range in private_ip_ranges:
                if ip_obj in private_range:
                    print(f"DNS Rebinding vulnerability detected: {domain} resolves to private IP {ip}")
                    return True  # Vulnerable to DNS rebinding

        print(f"No DNS Rebinding vulnerability detected for {domain}.")
        return False  # No DNS rebinding vulnerability detected
    except socket.error as e:
        print(f"Error resolving {domain}: {e}")
        return False  # Unable to resolve domain or detect DNS rebinding
    


def check_tls_weak_ciphers(url):
    """
    Scans the target URL for weak TLS cipher vulnerabilities.

    Args:
        url (str): The URL of the target service to check.

    Returns:
        bool: True if the service is using weak TLS ciphers, otherwise False.
    """
    # Ensure the URL starts with http:// or https://
    if not url.startswith(('http://', 'https://')):
        raise ValueError("The URL must start with 'http://' or 'https://'.")

    parsed_url = urlparse(url)
    host = parsed_url.hostname
    port = parsed_url.port or 443  # Default to HTTPS port if none is provided
    weak_ciphers = ["RC4", "MD5", "DES", "3DES"]  # List of weak ciphers to check

    try:
        # Create an SSL context
        context = ssl.create_default_context()

        # Create a connection to the server
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get the cipher used by the connection
                cipher = ssock.cipher()[0]
                
                # Check if the cipher is in the list of weak ciphers
                if any(weak_cipher in cipher for weak_cipher in weak_ciphers):
                    print(f"Weak cipher detected: {cipher}")
                    return True  # Vulnerable to weak cipher
                
        print("No weak cipher detected.")
        return False  # No weak cipher detected
    except (ssl.SSLError, socket.error) as e:
        print(f"Error during SSL/TLS handshake: {e}")
        return False  # Unable to test due to SSL error or connection issue