import re
from github import Github

def scan_for_insecure_configuration(file_content):
    """
    Scans for insecure configurations, such as non-HTTPS URLs, in the repository files.
    """
    insecure_patterns = [
        r'http://',  # Look for non-HTTPS URLs
        r'allow_http\s*=\s*True',  # Check for flags explicitly allowing HTTP
        r'enable_https\s*=\s*False',  # Flags disabling HTTPS
    ]
    for pattern in insecure_patterns:
        if re.search(pattern, file_content, re.IGNORECASE):
            return True
    return False

def scan_github_repository_for_insecure_configs(repo_url, github_token):
    """
    Scans a GitHub repository for insecure configurations.
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

                # Check for insecure configurations
                if scan_for_insecure_configuration(content_data):
                    vulnerabilities[file_content.path] = "Insecure configuration detected (e.g., non-HTTPS URLs)"
            except Exception as e:
                print(f"Error decoding {file_content.path}: {e}")

    return vulnerabilities
