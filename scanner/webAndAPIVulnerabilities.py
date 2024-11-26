import requests
import jwt
import sys

def check_jwt_weak_signing(target_url):
    """
    Tests if the target URL is vulnerable to weak JWT signing (using the 'none' algorithm).
    
    Args:
        target_url (str): The URL of the server to test.
        
    Returns:
        bool: True if vulnerable (weak JWT signing), False otherwise.
    """
    # Create a JWT with "none" algorithm (no signature)
    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "admin"}
    
    # Encode the JWT token with no secret (for "none" algorithm)
    token = jwt.encode(payload, "", algorithm=None, headers=header)
    
    # Prepare the Authorization header with the crafted token
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    try:
        # Send the GET request with the Authorization header containing the weak JWT
        response = requests.get(target_url, headers=headers, timeout=10)
        
        # Check if the server accepted the request with an unsigned JWT (indicating vulnerability)
        if response.status_code == 200:
            print(f"Vulnerable: Weak JWT signing detected on {target_url}.", file=sys.stderr)
            return True  # Vulnerable
        
        print(f"Not Vulnerable: JWT signing issue not detected on {target_url}.", file=sys.stderr)
        return False  # Not vulnerable
    
    except requests.RequestException as e:
        # Log any request-related errors
        print(f"Error with the request to {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test
    

def check_http_parameter_pollution(target_url):
    """
    Tests if the server is vulnerable to HTTP Parameter Pollution (HPP).
    
    Args:
        target_url (str): The URL of the server to test.
        
    Returns:
        bool: True if vulnerable, False otherwise.
    """
    # Duplicate parameter payload
    params = {
        "param": "value1",  # First occurrence of the parameter
        "param": "value2"   # Second occurrence of the same parameter
    }

    try:
        # Send the GET request with the duplicate parameters
        response = requests.get(target_url, params=params, timeout=10)
        
        # Check if the server returned both parameter values in the response (indicating HPP vulnerability)
        if "value1" in response.text and "value2" in response.text:
            print(f"Vulnerable: HTTP Parameter Pollution detected on {target_url}.", file=sys.stderr)
            return True  # Vulnerable to HTTP Parameter Pollution
        
        print(f"Not Vulnerable: No HTTP Parameter Pollution detected on {target_url}.", file=sys.stderr)
        return False  # Not vulnerable
    
    except requests.RequestException as e:
        # Log any request-related errors
        print(f"Error with the request to {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test
    

def check_graphql_query_depth(target_url):
    """
    Tests if a GraphQL endpoint is vulnerable to deep query attacks (query depth).
    
    Args:
        target_url (str): The target URL to send the GraphQL query to.
        
    Returns:
        bool: True if the endpoint is vulnerable, False otherwise.
    """
    # Nested query payload (deep query)
    query = """
    query {
      user {
        posts {
          comments {
            replies {
              content
            }
          }
        }
      }
    }
    """
    
    try:
        response = requests.post(target_url, json={"query": query}, timeout=10)
        
        # Check if the response is successful and there are no errors in the response JSON
        if response.status_code == 200 and "errors" not in response.json():
            print(f"Vulnerable: GraphQL query depth attack is allowed on {target_url}.", file=sys.stderr)
            return True  # Vulnerable to deep query
        print(f"Not Vulnerable: Server rejected the deep query on {target_url}.", file=sys.stderr)
        return False  # Not vulnerable
    
    except requests.RequestException as e:
        # Log any request-related issues (e.g., timeout, network errors)
        print(f"Error with the request to {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test
    

def check_client_side_validation_bypass(target_url):
    """
    Tests if the application is vulnerable to client-side validation bypass
    by submitting an invalid email that would typically be blocked by client-side validation.
    
    Args:
        target_url (str): The target URL to send the payload to.
        
    Returns:
        bool: True if vulnerable, False otherwise.
    """
    # Payload with invalid data (e.g., bypassing a field's required validation)
    payload = {
        "username": "admin",
        "email": "invalid-email"  # Bypassing client-side email validation
    }
    
    try:
        response = requests.post(target_url, data=payload, timeout=10)
        
        # Check if the response code is 200, which indicates the server did not block the request
        if response.status_code == 200:
            print("Vulnerable: Client-side validation bypassed.", file=sys.stderr)
            return True  # Vulnerable
        
        print("Not Vulnerable: Server blocked the request.", file=sys.stderr)
        return False  # Not Vulnerable
    
    except requests.RequestException as e:
        # Log any error related to the request (e.g., network error, timeout)
        print(f"Error with the request to {target_url}: {e}", file=sys.stderr)
        return False  # Unable to test