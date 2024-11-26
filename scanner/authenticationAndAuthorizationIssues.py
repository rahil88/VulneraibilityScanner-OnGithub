import re
import jwt

def has_weak_authorization_github(file_content):
    """
    Checks for patterns that indicate weak authorization checks in the code.
    """
    if re.search(r'\.get\(.*/admin.*\)', file_content) and "Authorization" not in file_content:
        return True
    return False

def is_session_hijacking_vulnerable_github(file_content):
    """
    Checks if session cookies are missing 'Secure' or 'HttpOnly' flags in the code.
    """
    if re.search(r'set_cookie\(.+["\']session.+["\'],.+Secure=False', file_content):
        return True  # Missing 'Secure' flag
    if re.search(r'set_cookie\(.+["\']session.+["\'],.+HttpOnly=False', file_content):
        return True  # Missing 'HttpOnly' flag
    return False

def is_idor_vulnerable_github(file_content):
    """
    Detects potential IDOR vulnerabilities by checking for direct user ID references in URLs.
    """
    if re.search(r'/{user_id}', file_content) and "Authorization" not in file_content:
        return True
    return False

def is_csrf_vulnerable_github(file_content):
    """
    Checks for missing CSRF token implementation in actions that modify data.
    """
    if re.search(r'post\(.+/profile/update', file_content) and "csrf_token" not in file_content:
        return True
    return False

def is_api_authentication_broken_github(file_content):
    """
    Detects lack of API authentication mechanisms by searching for API call patterns without tokens or keys.
    """
    if re.search(r'requests\.(get|post|put|delete)\(.+\)', file_content) and "Authorization" not in file_content:
        return True
    return False

def is_jwt_insecure_github(file_content):
    """
    Verifies if JWT usage is insecure by checking for missing expiration fields or insecure algorithms.
    """
    if re.search(r'jwt\.encode\(', file_content) and "exp" not in file_content:
        return True  # Missing expiration
    if re.search(r'algorithm=["\']none["\']', file_content):
        return True  # Insecure algorithm
    return False

def scan_file_for_vulnerabilities(file_content, file_path):
    """
    Scans a single file for vulnerabilities using the above checks.
    """
    vulnerabilities = {}
    if has_weak_authorization_github(file_content):
        vulnerabilities["Weak Authorization"] = f"Potential weak authorization checks in {file_path}"
    if is_session_hijacking_vulnerable_github(file_content):
        vulnerabilities["Session Hijacking"] = f"Potential session hijacking vulnerability in {file_path}"
    if is_idor_vulnerable_github(file_content):
        vulnerabilities["IDOR"] = f"Potential IDOR vulnerability in {file_path}"
    if is_csrf_vulnerable_github(file_content):
        vulnerabilities["CSRF"] = f"Potential missing CSRF protection in {file_path}"
    if is_api_authentication_broken_github(file_content):
        vulnerabilities["Broken API Authentication"] = f"Potential broken API authentication in {file_path}"
    if is_jwt_insecure_github(file_content):
        vulnerabilities["Insecure JWT"] = f"Potential insecure JWT implementation in {file_path}"
    return vulnerabilities