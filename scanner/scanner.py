from github import Github
from github.GithubException import GithubException
from dotenv import load_dotenv
import os
import re

import apiAndInputHandlingIssue
import apiSpecifications
import authenticationAndAuthorizationIssues
import commonConfigurationIssues
import businessLogicVulnerabilities
import config
import configurationAndDeploymentIssues
import crossSiteScripting
import crytographicAndStorageVulnerabilities
import discoveryOfSensitiveFiles
import injection
import injectionAndCodeExecutionVulnerabilities
import localFileInclusion
import logicTesting
import networkAndProtocol
import remoteCommandExecution
import versionBasedVulnerabilitiesDetection
import webAndAPIVulnerabilities
import webSecurityVulnerabilities
import websiteFingerprinting

# Add more vulnerability checks as needed
vulnerability_checks = {
    "SQL Injection vulnerability": injection.is_sql_injection_vulnerable,
    # "NoSQL Injection vulnerability": is_nosql_injection_vulnerable,
    "Cross-Site Scripting (XSS) vulnerability": crossSiteScripting.is_xss_vulnerable,
    "Command Injection vulnerability": remoteCommandExecution.is_command_injection_vulnerable,
    "LDAP Injection vulnerability": injection.is_ldap_injection_vulnerable,
    "XML External Entities (XXE) vulnerability": injection.is_xxe_vulnerable,
    "Weak Password Policy": discoveryOfSensitiveFiles.is_weak_password_policy,
    "Session Hijacking vulnerability": authenticationAndAuthorizationIssues.is_session_hijacking_vulnerable_github,
    "Insufficient Session Expiration vulnerability": apiAndInputHandlingIssue.is_session_expiration_insufficient_github,
    "Unsecured JWT Tokens": authenticationAndAuthorizationIssues.is_jwt_insecure_github,
    "Unsafe Object Deserialization vulnerability": remoteCommandExecution.is_unsafe_deserialization,
    "Exposed Debugging/Stack Traces": websiteFingerprinting.has_exposed_debug_info,
    "Default Credentials": commonConfigurationIssues.scan_for_default_credentials,
    "Directory Indexing vulnerability": websiteFingerprinting.is_directory_indexing_enabled,
    "Cross-Site Request Forgery (CSRF) vulnerability": authenticationAndAuthorizationIssues.is_csrf_vulnerable_github,
    "Insecure Direct Object References (IDOR) vulnerability": authenticationAndAuthorizationIssues.is_idor_vulnerable_github,
    "Hardcoded Credentials": discoveryOfSensitiveFiles.has_hardcoded_credentials,
    "Insecure Storage of Sensitive Data": discoveryOfSensitiveFiles.is_insecure_storage_used,
    "Unencrypted Data Transmission": discoveryOfSensitiveFiles.is_unencrypted_data_transmitted,
    "Weak Cryptographic Implementations": commonConfigurationIssues.scan_for_weak_crypto,
    "Broken API Authentication": authenticationAndAuthorizationIssues.is_api_authentication_broken_github,
    "Missing Rate-Limiting in APIs": apiSpecifications.has_missing_rate_limiting_github,
    "Excessive Data Exposure in APIs": apiSpecifications.is_excessive_data_exposed_github,
    "Mass Assignment": apiAndInputHandlingIssue.is_mass_assignment_possible_github,
    "Known Vulnerabilities in Dependencies": versionBasedVulnerabilitiesDetection.check_known_vulnerabilities,
    "Outdated Libraries": versionBasedVulnerabilitiesDetection.check_outdated_libraries,
    "Improper CORS Configuration": commonConfigurationIssues.scan_for_cors_misconfiguration,
    # "Unrestricted File Uploads": commonConfigurationIssues.is_file_upload_unrestricted,
    # "MIME Type Spoofing": commonConfigurationIssues.is_mime_type_spoofing_possible,
    "Directory Traversal": websiteFingerprinting.is_directory_traversal_possible,
    "Remote File Inclusion": localFileInclusion.is_remote_file_inclusion_vulnerable,
    "Insecure Framework Configuration": commonConfigurationIssues.scan_for_insecure_framework_configuration,
    "Unsafe eval() Usage": apiAndInputHandlingIssue.uses_unsafe_eval_github,
    "Insufficient Logging": discoveryOfSensitiveFiles.has_insufficient_logging,
    "Sensitive Data Logging": discoveryOfSensitiveFiles.logs_sensitive_data,
    # "Open Redirect": commonConfigurationIssues.is_open_redirect_vulnerable,
    "Weak Authorization Checks": authenticationAndAuthorizationIssues.has_weak_authorization_github,
    "Application Workflow Manipulation": logicTesting.can_manipulate_workflow,
    "Unpatched Web Server": versionBasedVulnerabilitiesDetection.is_web_server_unpatched,
    "Inadequate Role-Based Access Control (RBAC)": commonConfigurationIssues.scan_for_inadequate_rbac,
    "Open Admin Panel": websiteFingerprinting.is_admin_panel_open,
    "Manipulation of Application Workflows": logicTesting.can_manipulate_workflow,
    "Insecure Dev/Test Environments in Production": configurationAndDeploymentIssues.check_insecure_dev_envs,
    "Server-Side Request Forgery (SSRF)": configurationAndDeploymentIssues.check_ssrf,
    "Subdomain Takeover": configurationAndDeploymentIssues.check_subdomain_takeover,
    "Improper Error Handling": businessLogicVulnerabilities.check_improper_error_handling_github,
    "Race Condition Exploits": businessLogicVulnerabilities.check_race_condition_github,
    "Inventory and Resource Manipulation": businessLogicVulnerabilities.check_inventory_manipulation_github,
    "Poor Random Number Generation": crytographicAndStorageVulnerabilities.check_poor_random_number,
    "Weak Hashing Algorithms for Passwords": crytographicAndStorageVulnerabilities.check_weak_hashing,
    "Insecure Cookie Flags (e.g., HttpOnly, Secure)": crytographicAndStorageVulnerabilities.check_insecure_cookie_flags,
    "Clickjacking": webSecurityVulnerabilities.check_clickjacking,
    "Unsafe Content Security Policy (CSP)": webSecurityVulnerabilities.check_csp,
    "HTML5 Web Storage Vulnerabilities": webSecurityVulnerabilities.check_html5_storage,
    "TLS/SSL Weak Cipher Suites": networkAndProtocol.check_tls_weak_ciphers,
    "DNS Rebinding": networkAndProtocol.check_dns_rebinding,
    "IP Spoofing Detection": networkAndProtocol.check_ip_spoofing,
    "Host Header Injection": injectionAndCodeExecutionVulnerabilities.check_host_header_injection,
    "JavaScript Prototype Pollution": injectionAndCodeExecutionVulnerabilities.check_js_prototype_pollution,
    "Server-Side Template Injection (SSTI)": injectionAndCodeExecutionVulnerabilities.check_ssti,
    "Client-Side Validation Bypass": webAndAPIVulnerabilities.check_client_side_validation_bypass,
    "GraphQL Query Depth/Complexity Attacks": webAndAPIVulnerabilities.check_graphql_query_depth,
    "HTTP Parameter Pollution": webAndAPIVulnerabilities.check_http_parameter_pollution,
    "JWT Weak Signing Algorithms": webAndAPIVulnerabilities.check_jwt_weak_signing,
}

# Load environment variables
load_dotenv()

# Access the token from environment variables
github_token = os.getenv("GITHUB_TOKEN")

if not github_token:
    raise Exception(
        "GitHub token not found. Please set GITHUB_TOKEN in your .env file."
    )
else:
    print("Token loaded successfully!")


# Function to return the attack method for each vulnerability
def get_attack_method(vuln_name):
    attack_methods = {
        "SQL Injection vulnerability": "Inject SQL code to manipulate queries (e.g., ' OR '1'='1').",
        "NoSQL Injection vulnerability": "Inject NoSQL syntax to manipulate database operations.",
        "Cross-Site Scripting (XSS) vulnerability": "Inject malicious scripts (e.g., <script>alert('XSS')</script>).",
        "Command Injection vulnerability": "Inject OS commands via vulnerable input fields.",
        "LDAP Injection vulnerability": "Manipulate LDAP queries through crafted inputs.",
        "XML External Entities (XXE) vulnerability": "Exploit XML parsers by injecting external entities.",
        "Weak Password Policy": "Allow weak or easily guessable passwords.",
        "Session Hijacking vulnerability": "Expose session tokens to hijacking attempts.",
        "Insufficient Session Expiration vulnerability": "Fail to properly invalidate sessions on logout.",
        "Unsecured JWT Tokens": "Allow tokens without proper encryption or signature.",
        "Unsafe Object Deserialization vulnerability": "Use of untrusted data in deserialization.",
        "Exposed Debugging/Stack Traces": "Exposes debugging or stack trace information.",
        "Default Credentials": "Application uses default, well-known credentials.",
        "Directory Indexing vulnerability": "Enable access to file directories directly.",
        "Cross-Site Request Forgery (CSRF) vulnerability": "Allow requests from an attacker without verification.",
        "Insecure Direct Object References (IDOR) vulnerability": "Expose direct access to objects via identifiers.",
        "Hardcoded Credentials": "Sensitive credentials are hardcoded in the application.",
        "Insecure Storage of Sensitive Data": "Store sensitive data without encryption.",
        "Unencrypted Data Transmission": "Transmit sensitive data without encryption.",
        "Weak Cryptographic Implementations": "Use outdated or weak cryptographic functions.",
        "Broken API Authentication": "API endpoints lack proper authentication checks.",
        "Missing Rate-Limiting in APIs": "APIs lack rate limits to prevent abuse.",
        "Excessive Data Exposure in APIs": "Exposes excessive data in API responses.",
        "Mass Assignment vulnerability": "Allow mass assignment of critical parameters.",
        "Known Vulnerabilities in Dependencies": "Use dependencies with known security vulnerabilities.",
        "Outdated Libraries": "Use outdated libraries with potential security risks.",
        "Improper CORS Configuration": "Misconfigured CORS headers allow cross-origin requests.",
        "Unrestricted File Uploads": "Allows malicious files to be uploaded without restriction.",
        "MIME Type Spoofing vulnerability": "Upload files with a misleading MIME type.",
        "Directory Traversal vulnerability": "Access restricted files by navigating the directory structure.",
        "Remote File Inclusion": "Inject remote file paths to execute external files on the server.",
        "Insecure Default Framework Configurations": "Rely on default framework settings, which may expose vulnerabilities.",
        "Unsafe use of eval() in JavaScript": "Allow untrusted data to be evaluated as code, leading to code injection.",
        "Insufficient Logging and Monitoring": "Fail to log critical events, making intrusion detection difficult.",
        "Logging of Sensitive Data": "Store sensitive data in logs, risking exposure of credentials or personal information.",
        "Open Redirects": "Redirect users to untrusted sites by manipulating URLs in parameters.",
        "Weak Authorization Checks": "Allow access to restricted actions or data due to insufficient authorization checks.",
        "Manipulation of Application Workflows": "Exploit workflow flaws to bypass steps or gain unintended access.",
        "Unpatched Web Servers": "Use web servers with known vulnerabilities due to lack of patching.",
        "Inadequate Role-Based Access Control (RBAC)": "Allow access to sensitive resources due to insufficient role checks.",
        "Open Admin Panels": "Expose administrative panels without proper access control, allowing unauthorized access.",
        ## New vulnerabilities
        "Host Header Injection": "Inject malicious Host headers to influence server behavior.",
        "Server-Side Template Injection (SSTI)": "Inject template code to execute arbitrary server-side commands.",
        "JavaScript Prototype Pollution": "Manipulate object prototypes to introduce unexpected behaviors.",
        "HTTP Parameter Pollution": "Inject duplicate HTTP parameters to bypass security checks.",
        "JWT Weak Signing Algorithms": "Exploit weak or none algorithms to forge JWT tokens.",
        "GraphQL Query Depth/Complexity Attacks": "Send overly complex or deep queries to exhaust server resources.",
        "Client-Side Validation Bypass": "Skip client-side validation and send malicious input to the server.",
        "Server-Side Request Forgery (SSRF)": "Trick the server into making malicious requests to other systems.",
        "Insecure Dev/Test Environments in Production": "Expose sensitive development/test configurations in production.",
        "Subdomain Takeover": "Claim unused subdomains pointing to external services.",
        "Clickjacking": "Embed malicious frames to trick users into clicking unintended elements.",
        "Unsafe Content Security Policy (CSP)": "Configure CSP in a way that allows malicious content execution.",
        "HTML5 Web Storage Vulnerabilities": "Exploit insecure data stored in web storage (e.g., localStorage).",
        "Insecure Cookie Flags (e.g., HttpOnly, Secure)": "Omit security flags, exposing cookies to theft or misuse.",
        "Poor Random Number Generation": "Use predictable random values in security-critical processes.",
        "Weak Hashing Algorithms for Passwords": "Use outdated hash algorithms, such as MD5 or SHA-1, for passwords.",
        "Race Condition Exploits": "Exploit timing issues to perform unauthorized actions.",
        "Improper Error Handling": "Reveal sensitive information through error messages.",
        "Inventory and Resource Manipulation": "Manipulate resource counts to exploit inventory systems.",
        "TLS/SSL Weak Cipher Suites": "Use weak encryption ciphers that compromise secure communication.",
        "DNS Rebinding": "Trick the victim's browser into executing malicious requests to private networks.",
        "IP Spoofing Detection": "Disguise malicious traffic as originating from a trusted IP.",
    }
    return attack_methods.get(vuln_name, "No specific attack method available.")


# Function to scan a single file for vulnerabilities
def scan_file(file_content, file_path):
    vulnerabilities = {}
    for vuln_name, check_function in vulnerability_checks.items():
        try:
            if check_function(file_content):  # Check the file content for vulnerabilities
                vulnerabilities[vuln_name] = {
                    "description": vuln_name,
                    "file_path": file_path,
                    "attack_method": get_attack_method(vuln_name),
                }
        except Exception as e:
            print(f"Error checking {vuln_name} in {file_path}: {e}")
    return vulnerabilities

# Function to scan the entire GitHub repository
def scan_github_repository(repo_url, github_token):
    vulnerabilities = {}  # Dictionary to store vulnerabilities found in the repo

    try:
        # Parse owner and repository name
        parts = repo_url.rstrip('/').split('/')
        owner, repo_name = parts[-2], parts[-1]

        # Print parsed details for debugging
        print(f"Parsed Owner: {owner}, Repository: {repo_name}")

        # Authenticate and fetch repository
        g = Github(github_token)
        repo = g.get_repo(f"{owner}/{repo_name}")

        # Print repository details
        print(f"Scanning repository: {repo.full_name}")

        # Get all files in the repository (including files in subdirectories)
        contents = repo.get_contents("")

        # Iterate over the files and directories
        while contents:
            file_content = contents.pop(0)
            
            # Skip README.md, .txt files, and node_modules folder
            if file_content.name.lower() == "readme.md" or file_content.name.endswith(".txt") or "node_modules" in file_content.path:
                print(f"Skipping {file_content.path}")
                continue  # Skip these files and folders
            # If it's a directory, recurse into it
            
            if file_content.type == "dir":
                print(f"Entering directory: {file_content.path}")
                contents.extend(repo.get_contents(file_content.path))  # Recurse into the directory
            else:
                # Log the file being scanned (no content output)
                print(f"Scanning file: {file_content.path}")
                
                # Read the file content
                file_data = file_content.decoded_content.decode('utf-8')
                
                # Check the file for vulnerabilities
                file_vulnerabilities = scan_file(file_data, file_content.path)
                if file_vulnerabilities:
                    print(f"Found vulnerabilities in {file_content.path}")
                    vulnerabilities[file_content.path] = file_vulnerabilities
                else:
                    print(f"No vulnerabilities found in {file_content.path}")

    except GithubException as e:
        if e.status == 404:
            print(f"GitHub API error: Repository '{owner}/{repo_name}' not found.")
            print("Ensure the repository URL is correct and the token has access.")
        else:
            print(f"GitHub API error: {e.status} - {e.data}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return vulnerabilities

# Main logic to run the vulnerability scanner
if __name__ == "__main__":
    repo_url = "https://github.com/DivyaMulchandani/Report-generation"  # Replace with your target repo URL
    github_token = os.getenv("GITHUB_TOKEN")  # GitHub token for authentication

    vulnerabilities = scan_github_repository(repo_url, github_token)

    if vulnerabilities:
        print("\nVulnerabilities found:")
        for file_path, vuln_list in vulnerabilities.items():
            print(f"File: {file_path}")
            for vuln_name, details in vuln_list.items():
                print(f"  - {details['description']}")
                print(f"    Attack Method: {details['attack_method']}")
    else:
        print("No vulnerabilities found.")