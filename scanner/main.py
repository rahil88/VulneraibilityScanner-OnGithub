if __name__ == "__main__":
    repo_url = "https://github.com/ziyanchasmawala/Recommendation-System"  # Replace with the target repository URL
    github_token = os.getenv("GITHUB_TOKEN")  # Use your GitHub token for authentication

    vulnerabilities = scan_github_repository(repo_url, github_token)

    if vulnerabilities:
        print("Vulnerabilities found:")
        for file_path, vuln_list in vulnerabilities.items():
            print(f"File: {file_path}")
            for vuln_name, details in vuln_list.items():
                print(f"  - {details['description']}")
                print(f"    Attack Method: {details['attack_method']}")
    else:
        print("No vulnerabilities found.")
