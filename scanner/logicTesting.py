import requests

def can_manipulate_workflow(url, parameter="status"):
    """
    Checks for potential application workflow manipulation by modifying a parameter's value.
    
    Parameters:
    - url (str): The target URL to check for workflow manipulation vulnerability.
    - parameter (str): The query parameter to modify (default is "status").
    
    Returns:
    - bool: True if the parameter manipulation is successful, otherwise False.
    """
    # Validate URL input
    if not isinstance(url, str) or not url.startswith("http"):
        raise ValueError("Invalid URL. Ensure the URL starts with 'http' or 'https'.")

    # Construct test URL with modified parameter
    test_url = f"{url}?{parameter}=approved"

    try:
        # Send GET request with modified parameter
        response = requests.get(test_url, timeout=5)

        # Check if the response reflects the manipulated value (e.g., "approved" in the response)
        if response.status_code == 200 and "approved" in response.text.lower():
            print(f"Workflow manipulation detected with parameter '{parameter}' set to 'approved'.")
            return True
        return False
    except requests.RequestException as e:
        # Handle connection errors and other request issues
        print(f"Error while testing workflow manipulation: {e}")
        return False