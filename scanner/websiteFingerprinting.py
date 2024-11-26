import requests
import logging

def is_admin_panel_open(url):
    """
    Checks if an open admin panel is accessible without authentication.

    Args:
        url (str): The base URL of the site to test for open admin panels.

    Returns:
        bool: True if an open admin panel is detected, False otherwise.
    """
    admin_urls = ["/admin", "/administrator", "/controlpanel"]

    try:
        # Test each admin panel URL
        for admin_url in admin_urls:
            test_url = f"{url}{admin_url}"
            logging.info(f"Testing for open admin panel at: {test_url}")
            response = requests.get(test_url, timeout=5)
            response.raise_for_status()  # Raise error for bad HTTP responses
            
            # If the page is accessible and contains 'admin', consider it an open panel
            if response.status_code == 200 and "admin" in response.text.lower():
                logging.warning(f"Open admin panel found at: {test_url}")
                return True  # Admin panel is open

        logging.info("No open admin panel found.")
        return False  # No open admin panel found

    except requests.RequestException as e:
        logging.error(f"Error accessing {url}: {e}")
        return False  # Unable to test due to network or HTTP error
    

def is_directory_traversal_possible(url):
    """
    Checks for directory traversal vulnerability by sending common directory traversal patterns.

    Args:
        url (str): The base URL of the site to test for directory traversal vulnerability.

    Returns:
        bool: True if directory traversal is possible, False otherwise.
    """
    # List of common directory traversal patterns for testing
    traversal_patterns = [
        "../../../../etc/passwd",  # Unix/Linux system
        "../../../windows/win.ini"  # Windows system
    ]
    
    try:
        # Test each traversal pattern
        for pattern in traversal_patterns:
            test_url = f"{url}/{pattern}"
            logging.info(f"Testing for directory traversal with pattern: {test_url}")
            response = requests.get(test_url, timeout=10)
            response.raise_for_status()  # Raise an error for bad responses

            # Check if the server returns sensitive system information
            if "root:" in response.text or "[extensions]" in response.text:
                logging.warning(f"Directory traversal possible with {test_url}")
                return True  # Indicates possible directory traversal vulnerability

        logging.info("No directory traversal vulnerability found.")
        return False  # No directory traversal vulnerability found

    except requests.RequestException as e:
        logging.error(f"Error accessing {url}: {e}")
        return False  # Unable to test due to network or HTTP error
    

def is_directory_indexing_enabled(url):
    """
    Checks if directory indexing is enabled by looking for directory listing indicators in HTTP responses.

    Args:
        url (str): The base URL of the site to check for directory indexing.

    Returns:
        bool: True if directory indexing is enabled, False otherwise.
    """
    try:
        # Construct test URL for the directory path
        test_url = f"{url}/testdir/"  # Test with a directory path

        # Send GET request to the test URL
        response = requests.get(test_url, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)

        # Look for directory listing indicators in the response text
        if "<title>Index of" in response.text or "Directory listing for" in response.text:
            logging.info(f"Directory indexing is enabled for {test_url}")
            return True  # Directory indexing is enabled

        logging.info(f"Directory indexing is not enabled for {test_url}")
        return False  # Directory indexing is not enabled

    except requests.RequestException as e:
        logging.error(f"Error accessing {test_url}: {e}")
        return False  # Unable to test due to network or HTTP error
    

def has_exposed_debug_info(url):
    """
    Scans responses for common debugging indicators such as stack traces or error messages.
    Useful for identifying pages with verbose error messages exposed.

    Args:
        url (str): The URL of the target page to check for exposed debug information.

    Returns:
        bool: True if debug information is exposed, False otherwise.
    """
    try:
        # Send GET request to the URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)

        # Common debug signatures to look for
        debug_signatures = [
            "Traceback (most recent call last)",
            "Exception:",
            "Error:",
            "Stacktrace:"
        ]
        
        # Check if any of the debug signatures are present in the response text
        if any(signature in response.text for signature in debug_signatures):
            logging.error(f"Exposed debug information found at {url}")
            return True  # Vulnerable: Exposed debug information
        
        logging.info(f"No exposed debug information found at {url}")
        return False  # Not Vulnerable

    except requests.RequestException as e:
        logging.error(f"Error while accessing {url}: {e}")
        return False  # Unable to test due to network or HTTP error