from github import Github
import os

# Function to fetch and scan GitHub repository contents
def scan_github_repository(repo_url, github_token):
    """
    Scans a GitHub repository for vulnerabilities.

    Parameters:
    - repo_url (str): GitHub repository URL.
    - github_token (str): Personal Access Token for GitHub.

    Returns:
    - dict: Vulnerabilities found in the repository.
    """
    # Parse repository owner and name from the URL
    try:
        parts = repo_url.rstrip('/').split('/')
        owner, repo_name = parts[-2], parts[-1]

        # Authenticate and get the repository
        g = Github(github_token)
        repo = g.get_repo(f"{owner}/{repo_name}")
        print(f"Scanning repository: {repo.full_name}")

        vulnerabilities = {}

        # Get all files in the repository
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                print(f"Scanning file: {file_content.path}")
                # Read the file content
                file_data = file_content.decoded_content.decode('utf-8')
                # Check the file for vulnerabilities
                file_vulnerabilities = scan_file(file_data, file_content.path)
                if file_vulnerabilities:
                    vulnerabilities[file_content.path] = file_vulnerabilities

        return vulnerabilities

    except Exception as e:
        print(f"Error scanning GitHub repository: {e}")
        return {}

# Function to scan a single file for vulnerabilities
def scan_file(file_content, file_path):
    vulnerabilities = {}
    for vuln_name, check_function in vulnerability_checks.items():
        try:
            if check_function(file_content):  # Adjust the check function as needed for file scanning
                vulnerabilities[vuln_name] = {
                    "description": vuln_name,
                    "file_path": file_path,
                    "attack_method": get_attack_method(vuln_name)
                }
        except Exception as e:
            print(f"Error checking {vuln_name} in {file_path}: {e}")
    return vulnerabilities
