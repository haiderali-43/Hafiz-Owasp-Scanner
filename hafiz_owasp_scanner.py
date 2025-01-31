import subprocess
import sys
import argparse
from urllib.parse import urlparse
import os
import threading
import logging
import json

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Setup logging
logging.basicConfig(filename='logs/scan_results.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    'A01:2021-Broken Access Control': ['sqlmap', 'nmap'],
    'A02:2021-Cryptographic Failures': ['openssl', 'nmap'],
    'A03:2021-Injection': ['sqlmap', 'xsser', 'XXEinjector', 'commix', 'nmap'],
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

# Save scan state to resume.cfg
def save_scan_state(state):
    with open('resume.cfg', 'w') as f:
        json.dump(state, f)

# Load scan state from resume.cfg
def load_scan_state():
    if os.path.exists('resume.cfg'):
        with open('resume.cfg', 'r') as f:
            return json.load(f)
    return {}

# Vulnerability check functions for OWASP Top 10
def check_broken_access_control(url):
    print("[+] Checking for Broken Access Control...")
    try:
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch", "--crawl=1"], check=True)
        logging.info("Broken Access Control check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Broken Access Control.")
        logging.error("Error in detecting Broken Access Control.")

def check_cryptographic_failures(url):
    print("[+] Checking for Cryptographic Failures...")
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        print("[+] Potential Cryptographic Failure: The site does not use HTTPS.")
        logging.warning("Potential Cryptographic Failure: The site does not use HTTPS.")
    else:
        print("[+] HTTPS is being used for communication.")
        logging.info("HTTPS is being used for communication.")

def check_injection(url):
    print("[+] Checking for SQL/NoSQL Injection...")
    try:
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch"], check=True)
        logging.info("SQL/NoSQL Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting SQL/NoSQL Injection vulnerabilities.")
        logging.error("Error in detecting SQL/NoSQL Injection vulnerabilities.")

    print("[+] Checking for HTML Injection...")
    try:
        subprocess.run(["xsser", "--url", url], check=True)
        logging.info("HTML Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting HTML Injection vulnerabilities.")
        logging.error("Error in detecting HTML Injection vulnerabilities.")

    print("[+] Checking for XXE Injection...")
    try:
        subprocess.run(["XXEinjector", "-u", url], check=True)
        logging.info("XXE Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting XXE Injection vulnerabilities.")
        logging.error("Error in detecting XXE Injection vulnerabilities.")

    print("[+] Checking for Command Injection...")
    try:
        subprocess.run(["commix", "--url", url], check=True)
        logging.info("Command Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Command Injection vulnerabilities.")
        logging.error("Error in detecting Command Injection vulnerabilities.")

    print("[+] Checking for LDAP Injection...")
    try:
        # Placeholder for LDAP injection check (using a hypothetical tool or custom script)
        subprocess.run(["ldap_injector_tool", "-u", url], check=True)
        logging.info("LDAP Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting LDAP Injection vulnerabilities.")
        logging.error("Error in detecting LDAP Injection vulnerabilities.")

    print("[+] Checking for XPath Injection...")
    try:
        # Placeholder for XPath injection check (using a hypothetical tool or custom script)
        subprocess.run(["xpath_injector_tool", "-u", url], check=True)
        logging.info("XPath Injection check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting XPath Injection vulnerabilities.")
        logging.error("Error in detecting XPath Injection vulnerabilities.")

def check_xss(url):
    print("[+] Checking for Cross-Site Scripting (XSS)...")
    try:
        subprocess.run(["xsser", "--url", url], check=True)
        logging.info("XSS check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting XSS vulnerabilities.")
        logging.error("Error in detecting XSS vulnerabilities.")

def check_insecure_design(url):
    print("[+] Checking for Insecure Design...")
    try:
        subprocess.run(["nmap", "--open", url], check=True)
        logging.info("Insecure Design check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Insecure Design.")
        logging.error("Error in detecting Insecure Design.")

def check_security_misconfiguration(url):
    print("[+] Checking for Security Misconfiguration...")
    try:
        subprocess.run(["nikto", "-h", url], check=True)
        subprocess.run(["nmap", "--script", "http-security-headers", url], check=True)
        logging.info("Security Misconfiguration check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Security Misconfiguration.")
        logging.error("Error in detecting Security Misconfiguration.")

def check_outdated_components(url):
    print("[+] Checking for Outdated Components...")
    try:
        subprocess.run(["nmap", "--script", "http-enum", url], check=True)
        subprocess.run(["retire", "--scan", url], check=True)
        logging.info("Outdated Components check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Outdated Components.")
        logging.error("Error in detecting Outdated Components.")

def check_authentication_failures(url):
    print("[+] Checking for Authentication Failures...")
    try:
        subprocess.run(["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", url, "http-get-form", "'/login:username=^USER^&password=^PASS^:F=incorrect'"], check=True)
        logging.info("Authentication Failures check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Authentication Failures.")
        logging.error("Error in detecting Authentication Failures.")

def check_software_integrity(url):
    print("[+] Checking for Software and Data Integrity Failures...")
    try:
        subprocess.run(["git", "ls-remote", url], check=True)
        logging.info("Software and Data Integrity Failures check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Software Integrity Failures.")
        logging.error("Error in detecting Software Integrity Failures.")

def check_logging_failures(url):
    print("[+] Checking for Logging and Monitoring Failures...")
    try:
        subprocess.run(["lynis", "audit", "system"], check=True)
        logging.info("Logging and Monitoring Failures check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting Logging and Monitoring Failures.")
        logging.error("Error in detecting Logging and Monitoring Failures.")

def check_ssrf(url):
    print("[+] Checking for SSRF (Server-Side Request Forgery)...")
    try:
        subprocess.run(["sqlmap", "-u", url, "--level=5", "--risk=3", "--batch"], check=True)
        logging.info("SSRF check completed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Error in detecting SSRF.")
        logging.error("Error in detecting SSRF.")

# Function to run checks in parallel
def run_checks_in_parallel(url, resume_state):
    threads = []
    checks = [
        check_broken_access_control,
        check_cryptographic_failures,
        check_injection,
        check_insecure_design,
        check_security_misconfiguration,
        check_outdated_components,
        check_authentication_failures,
        check_software_integrity,
        check_logging_failures,
        check_ssrf
    ]

    for check in checks:
        if check.__name__ not in resume_state.get('completed_checks', []):
            thread = threading.Thread(target=check, args=(url,))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    # Update resume state
    resume_state['completed_checks'] = [check.__name__ for check in checks]
    save_scan_state(resume_state)

# Main function
def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Bug Bounty OWASP Top 10 Scanner - Scan websites for vulnerabilities using CLI tools.")
    parser.add_argument("-u", "--url", required=True, help="URL of the target website")
    parser.add_argument("--rps", default=5, type=int, help="Requests per second for scanning (default: 5)")
    parser.add_argument("-c", "--config", help="Path to configuration file")

    args = parser.parse_args()

    url = args.url
    request_per_second = args.rps

    # Load configuration file if provided
    if args.config:
        with open(args.config, 'r') as config_file:
            config = json.load(config_file)
            url = config.get('url', url)
            request_per_second = config.get('rps', request_per_second)

    # Run tools check once
    show_banner()
    check_tools_once()
    

    # Load resume state
    resume_state = load_scan_state()

    # Run automated scans using relevant tools for each OWASP category
    print("[+] Running scans for OWASP Top 10 vulnerabilities...")
    logging.info("Starting scans for OWASP Top 10 vulnerabilities on %s", url)

    run_checks_in_parallel(url, resume_state)

    print("[+] Scans completed. Check the log file for detailed results.")
    logging.info("Scans completed for %s", url)

# Run main function
if __name__ == "__main__":
    main()