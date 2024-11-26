import re
import datetime

def is_mass_assignment_possible_github(file_content):
    """
    Simulates testing for mass assignment vulnerability in a GitHub file by searching
    for suspicious patterns in code such as arbitrary parameter assignments.
    """
    # Search for direct assignments that could imply mass assignment risks
    if re.search(r'assign_attributes|mass_assignment|update_attributes', file_content):
        return True
    return False

def is_session_expiration_insufficient_github(file_content):
    """
    Checks for insufficient session expiration settings in the file content by analyzing
    cookie configurations or session management code.
    """
    # Look for session configurations with no expiration or excessive duration
    if re.search(r'session\.set_cookie\(.+?expires=None', file_content) or \
       re.search(r'session\.set_cookie\(.+?expires=\d+.+?(days|hours)', file_content):
        match = re.search(r'expires=(\d+)', file_content)
        if match and int(match.group(1)) > 7:
            return True
    return False

def uses_unsafe_eval_github(file_content):
    """
    Checks if the file content uses eval(), which is unsafe and prone to vulnerabilities.
    """
    if "eval(" in file_content:
        return True
    return False

def scan_file_for_vulnerabilities(file_content, file_path):
    """
    Scans a single file for vulnerabilities using the above checks.
    """
    vulnerabilities = {}
    if is_mass_assignment_possible_github(file_content):
        vulnerabilities["Mass Assignment"] = f"Potential mass assignment risk in {file_path}"
    if is_session_expiration_insufficient_github(file_content):
        vulnerabilities["Insufficient Session Expiration"] = f"Potential session expiration issue in {file_path}"
    if uses_unsafe_eval_github(file_content):
        vulnerabilities["Unsafe eval"] = f"Unsafe eval() usage in {file_path}"
    return vulnerabilities