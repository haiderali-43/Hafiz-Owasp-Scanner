import subprocess
import sys
import argparse
from urllib.parse import urlparse
import os

# Display Banner
def show_banner():
    banner = """
    ██████╗  █████╗ ███████╗██╗███████╗     ██████╗ ██╗    ██╗ █████╗ ███████╗
    ██╔══██╗██╔══██╗██╔════╝██║██╔════╝     ██╔══██╗██║    ██║██╔══██╗██╔════╝
    ██████╔╝███████║███████╗██║█████╗       ██████╔╝██║ █╗ ██║███████║███████╗
    ██╔═══╝ ██╔══██║╚════██║██║██╔══╝       ██╔═══╝ ██║███╗██║██╔══██║╚════██║
    ██║     ██║  ██║███████║██║███████╗     ██║     ╚███╔███╔╝██║  ██║███████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝     ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝

              🛡️ OWASP Top 10 Vulnerability Scanner by Hafiz 🛡️
    """
    print(banner)

# List of required tools for each OWASP Top 10 category
REQUIRED_TOOLS = {
    'A01:2021-Broken Access Control': ['sqlmap', 'nmap',],
    'A02:2021-Cryptographic Failures': ['openssl', 'nmap'],
    'A03:2021-Injection': ['sqlmap', 'nmap'],
    'A04:2021-Insecure Design': ['nmap'],
    'A05:2021-Security Misconfiguration': ['nikto', 'nmap'],
    'A06:2021-Vulnerable and Outdated Components': ['nmap', 'retire.js'],
    'A07:2021-Identification and Authentication Failures': ['hydra', 'john'],
    'A08:2021-Software and Data Integrity Failures': ['nmap', 'git'],
    'A09:2021-Security Logging and Monitoring Failures': ['lynis', 'nmap'],
    'A10:2021-Server-Side Request Forgery': ['sqlmap', 'nmap']
}

# Check if the necessary tools are installed
def check_tools():
    missing_tools = []
    for tools in REQUIRED_TOOLS.values():
        for tool in tools:
            try:
                subprocess.run([tool, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                missing_tools.append(tool)

    if missing_tools:
        print("[!] Missing tools:", ", ".join(missing_tools))
        print("[*] Please install the missing tools before running the script.")
        sys.exit(1)
    else:
        print("[+] All required tools are installed!")

# Check if tools have been checked previously
def check_tools_once():
    if not os.path.exists(".tools_checked"):
        print("[+] Checking if required tools are installed...")
        check_tools()
        with open(".tools_checked", "w") as f:
            f.write("Tools checked successfully.")
    else:
        print("[+] Tools check skipped. Tools were already verified.")

# Vulnerability check functions for OWASP Top 10
def check_broken_access_control(url):
    print("[+] Checking for Broken Access Control...")
    try:
        # Run a simple SQLMap test to check for broken access control
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch", "--crawl=1"], check=True)
        subprocess.run(["sqlmap",url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Broken Access Control.")

def check_cryptographic_failures(url):
    print("[+] Checking for Cryptographic Failures...")
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        print("[+] Potential Cryptographic Failure: The site does not use HTTPS.")
    else:
        print("[+] HTTPS is being used for communication.")

def check_injection(url):
    print("[+] Checking for SQL/NoSQL Injection...")
    try:
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch"], check=True)
        subprocess.run(["sqlmap",url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Injection vulnerabilities.")

def check_insecure_design(url):
    print("[+] Checking for Insecure Design...")
    try:
        subprocess.run(["nmap", "--open", url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Insecure Design.")

def check_security_misconfiguration(url):
    print("[+] Checking for Security Misconfiguration...")
    try:
        subprocess.run(["nikto", "-h", url], check=True)
        subprocess.run(["nmap", "--script", "http-security-headers", url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Security Misconfiguration.")

def check_outdated_components(url):
    print("[+] Checking for Outdated Components...")
    try:
        subprocess.run(["nmap", "--script", "http-enum", url], check=True)
        subprocess.run(["retire", "--scan", url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Outdated Components.")

def check_authentication_failures(url):
    print("[+] Checking for Authentication Failures...")
    try:
        subprocess.run(["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", url, "http-get-form", "'/login:username=^USER^&password=^PASS^:F=incorrect'"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Authentication Failures.")

def check_software_integrity(url):
    print("[+] Checking for Software and Data Integrity Failures...")
    try:
        subprocess.run(["git", "ls-remote", url], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Software Integrity Failures.")

def check_logging_failures(url):
    print("[+] Checking for Logging and Monitoring Failures...")
    try:
        subprocess.run(["lynis", "audit", "system"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Logging and Monitoring Failures.")

def check_ssrf(url):
    print("[+] Checking for SSRF (Server-Side Request Forgery)...")
    try:
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error in detecting SSRF.")

# Main function
def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Bug Bounty OWASP Top 10 Scanner - Scan websites for vulnerabilities using CLI tools.")
    parser.add_argument("-u", "--url", required=True, help="URL of the target website")
    parser.add_argument("--rps", default=5, type=int, help="Requests per second for scanning (default: 5)")

    args = parser.parse_args()

    url = args.url
    request_per_second = args.rps

    # Run tools check once
    check_tools_once()

    # Run automated scans using relevant tools for each OWASP category
    print("[+] Running scans for OWASP Top 10 vulnerabilities...")

    check_broken_access_control(url)
    check_cryptographic_failures(url)
    check_injection(url)
    check_insecure_design(url)
    check_security_misconfiguration(url)
    check_outdated_components(url)
    check_authentication_failures(url)
    check_software_integrity(url)
    check_logging_failures(url)
    check_ssrf(url)

# Run main function
if __name__ == "__main__":
    main()
