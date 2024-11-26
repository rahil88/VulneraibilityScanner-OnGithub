import re

def is_excessive_data_exposed_github(file_content):
    """
    Checks if a file suggests excessive data exposure, such as large datasets
    being returned in API responses or data dumps.
    """
    # Look for patterns indicating large data exposure
    if re.search(r'\.json\(\)\s*>\s*\d+', file_content):  # Example: len(response.json()) > 50
        return True
    if re.search(r'return\s+.+?\[.*?\]', file_content):  # Example: returning large arrays
        return True
    return False

def has_missing_rate_limiting_github(file_content):
    """
    Checks for missing rate limiting in code by analyzing loops or repeated calls
    without delay or limit.
    """
    # Check for loops making multiple rapid requests without delays
    if re.search(r'for\s+\w+\s+in\s+range\(.+?\):.*?requests\.get', file_content, re.DOTALL):
        if not re.search(r'time\.sleep\(', file_content):  # No delay mechanism
            return True
    return False

def scan_file_for_api_vulnerabilities(file_content, file_path):
    """
    Scans a single file for API vulnerabilities using the above checks.
    """
    vulnerabilities = {}
    if is_excessive_data_exposed_github(file_content):
        vulnerabilities["Excessive Data Exposure"] = f"Potential excessive data exposure in {file_path}"
    if has_missing_rate_limiting_github(file_content):
        vulnerabilities["Missing Rate Limiting"] = f"Potential missing rate limiting in {file_path}"
    return vulnerabilities