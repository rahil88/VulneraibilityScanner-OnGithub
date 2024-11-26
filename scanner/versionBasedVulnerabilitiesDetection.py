import requests
import sys
import subprocess
import json


def is_web_server_unpatched(url):
    """
    Checks if the server is using an outdated version by inspecting the 'Server' header.
    It identifies well-known outdated versions (e.g., Apache, Nginx, IIS).
    
    Args:
        url (str): The URL of the web server to check.
        
    Returns:
        bool: True if the server is unpatched (outdated), False otherwise.
    """
    try:
        response = requests.head(url, timeout=5)
        
        # Check for 'Server' header and inspect known outdated versions
        server_header = response.headers.get("Server", "")
        outdated_servers = ["Apache/2.2", "nginx/1.12", "IIS/6.0"]  # Example outdated versions
        
        # If the server header contains any of the outdated versions, return True
        for outdated in outdated_servers:
            if outdated in server_header:
                print(f"Unpatched web server detected: {server_header}", file=sys.stderr)
                return True
        
    except requests.RequestException as e:
        # Log errors related to the request itself (e.g., timeout, DNS issues, etc.)
        print(f"Error making request to {url}: {e}", file=sys.stderr)
        return False  # If we can't determine, we assume it's not unpatched
    
    return False  # If no outdated server version is found



def check_outdated_libraries(dependency_manager="npm"):
    """
    Checks for outdated libraries using either npm or pip.
    Compatible with CI/CD environments like GitHub Actions.
    
    Args:
        dependency_manager (str): The dependency manager to use. Can be "npm" or "pip".
        
    Returns:
        dict: The details of outdated libraries found (if any).
        None: If no outdated libraries were found or in case of error.
    """
    if dependency_manager == "npm":
        command = ["npm", "outdated", "--json"]
    elif dependency_manager == "pip":
        command = ["pip", "list", "--outdated", "--format", "json"]
    else:
        raise ValueError("Unsupported dependency manager")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        outdated_libraries = json.loads(result.stdout)

        if outdated_libraries:
            return outdated_libraries  # Returns details of outdated libraries found
        return None  # No outdated libraries found

    except subprocess.CalledProcessError as e:
        print(f"Error during outdated libraries check: {e}", file=sys.stderr)
        return None  # If there is an error (e.g., command failed), return None
    except FileNotFoundError:
        print(f"Error: {dependency_manager} not found. Ensure it's installed.", file=sys.stderr)
        return None  # Handle case where the dependency manager is not installed
    except json.JSONDecodeError:
        print("Error: Could not parse the output from the outdated libraries check.", file=sys.stderr)
        return None  # Handle cases where JSON parsing fails
    

def check_known_vulnerabilities(dependency_manager="npm"):
    """
    Checks for known vulnerabilities in dependencies using either npm or pip.
    Compatible with CI/CD environments like GitHub Actions.
    
    Args:
        dependency_manager (str): The dependency manager to use. Can be "npm" or "pip".
        
    Returns:
        dict: The details of vulnerabilities found (if any).
        None: If no vulnerabilities were found.
    """
    if dependency_manager == "npm":
        command = ["npm", "audit", "--json"]
    elif dependency_manager == "pip":
        command = ["pip-audit", "--format", "json"]
    else:
        raise ValueError("Unsupported dependency manager")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        vulnerabilities = json.loads(result.stdout)

        if vulnerabilities:
            return vulnerabilities  # Returns details of vulnerabilities found
        return None  # No vulnerabilities found

    except subprocess.CalledProcessError as e:
        print(f"Error during vulnerability check: {e}", file=sys.stderr)
        return None  # If there is an error (e.g., command failed), return None
    except FileNotFoundError:
        print(f"Error: {dependency_manager} not found. Ensure it's installed.", file=sys.stderr)
        return None  # Handle case where the dependency manager is not installed
    except json.JSONDecodeError:
        print("Error: Could not parse the output from the vulnerability scan.", file=sys.stderr)
        return None  # Handle cases where JSON parsing fails