import re
from github import Github

def scan_for_default_credentials(file_content):
    """
    Scans for hardcoded default credentials in the repository files.
    """
    default_creds_patterns = [
        r'username\s*=\s*[\'"](admin|root|user)[\'"]',
        r'password\s*=\s*[\'"](admin|root|password)[\'"]'
    ]
    for pattern in default_creds_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_for_inadequate_rbac(file_content):
    """
    Scans for inadequate role-based access control (RBAC) in the repository files.
    """
    rbac_patterns = [
        r'if\s+user\.role\s*==\s*[\'"]admin[\'"]',  # Hardcoded role checks
        r'if\s+.*permission\s*==\s*None',          # Missing permission validation
    ]
    for pattern in rbac_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_for_insecure_framework_configuration(file_content):
    """
    Looks for insecure configurations in framework settings (e.g., Django DEBUG mode).
    """
    framework_patterns = [
        r'DEBUG\s*=\s*True',  # Django insecure debug mode
        r'SECRET_KEY\s*=\s*[\'"]\w+[\'"]'  # Hardcoded secret keys
    ]
    for pattern in framework_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_for_weak_crypto(file_content):
    """
    Detects weak cryptographic algorithms in the repository files.
    """
    weak_crypto_patterns = [
        r'AES-\d{3}-ECB',  # ECB mode is weak
        r'MD5\(',          # MD5 is outdated
        r'SHA1\(',         # SHA1 is outdated
    ]
    for pattern in weak_crypto_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_for_cors_misconfiguration(file_content):
    """
    Scans for insecure CORS configurations in the code.
    """
    cors_patterns = [
        r'Access-Control-Allow-Origin\s*:\s*[\'"]\*',  # Wildcard CORS
        r'Access-Control-Allow-Credentials\s*:\s*true',  # Allow credentials with wildcard
    ]
    for pattern in cors_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_github_repository(repo_url, github_token):
    """
    Scans a GitHub repository for vulnerabilities by analyzing its files.
    """
    g = Github(github_token)
    repo_name = "/".join(repo_url.split('/')[-2:])
    repo = g.get_repo(repo_name)
    contents = repo.get_contents("")
    vulnerabilities = {}

    while contents:
        file_content = contents.pop(0)
        if file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
        else:
            try:
                content_data = file_content.decoded_content.decode('utf-8')
                file_vulnerabilities = {}

                # Check for specific vulnerabilities
                if scan_for_default_credentials(content_data):
                    file_vulnerabilities["Default Credentials"] = "Hardcoded default credentials detected"
                if scan_for_inadequate_rbac(content_data):
                    file_vulnerabilities["Inadequate RBAC"] = "Potential inadequate RBAC implementation"
                if scan_for_insecure_framework_configuration(content_data):
                    file_vulnerabilities["Insecure Framework Configuration"] = "Insecure framework configuration found"
                if scan_for_weak_crypto(content_data):
                    file_vulnerabilities["Weak Cryptography"] = "Weak cryptographic algorithm used"
                if scan_for_cors_misconfiguration(content_data):
                    file_vulnerabilities["CORS Misconfiguration"] = "Potential insecure CORS configuration"

                if file_vulnerabilities:
                    vulnerabilities[file_content.path] = file_vulnerabilities
            except Exception as e:
                print(f"Error decoding {file_content.path}: {e}")

    return vulnerabilities

