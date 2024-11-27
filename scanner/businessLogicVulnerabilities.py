import re

def check_improper_error_handling_github(file_content):
    """
    Checks for patterns that may indicate improper error handling in the code.
    """
    error_patterns = [
        r'print\(.*exception.*\)',  # Printing exceptions
        r'print\(.*error.*\)',      # Printing generic errors
        r'traceback\.format_exc\(', # Printing stack traces
        r'Exception as e'           # Catch-all exception handling
    ]
    for pattern in error_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def check_race_condition_github(file_content):
    """
    Scans for code patterns indicative of potential race conditions.
    """
    race_condition_patterns = [
        r'threading\.Thread',       # Use of threads
        r'asyncio\.create_task',    # Async tasks that may race
        r'concurrent\.futures'     # ThreadPoolExecutor or similar
    ]
    for pattern in race_condition_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def check_inventory_manipulation_github(file_content):
    """
    Looks for potential inventory manipulation by analyzing payload handling.
    """
    inventory_patterns = [
        r'quantity\s*=\s*[0-9]+',     # Hardcoded quantities
        r'request\.json\[["\']quantity["\']\]',  # Handling quantity in request
        r'if\s+.*quantity.*'          # Logical checks involving quantity
    ]
    for pattern in inventory_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_file_for_vulnerabilities(file_content, file_path):
    """
    Scans a single file for vulnerabilities using the above checks.
    """
    vulnerabilities = {}
    if check_improper_error_handling_github(file_content):
        vulnerabilities["Improper Error Handling"] = f"Potential improper error handling in {file_path}"
    if check_race_condition_github(file_content):
        vulnerabilities["Race Condition"] = f"Potential race condition in {file_path}"
    if check_inventory_manipulation_github(file_content):
        vulnerabilities["Inventory Manipulation"] = f"Potential inventory manipulation in {file_path}"
    return vulnerabilities