import os
import argparse
import shutil
import threading

# Check if a tool is installed
def check_tool(tool_name):
    return shutil.which(tool_name) is not None

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

# Check if all required tools are installed
def check_required_tools():
    required_tools = ["nmap", "nikto", "sqlmap", "wfuzz"]
    missing_tools = [tool for tool in required_tools if not check_tool(tool)]

    if missing_tools:
        print(f"\n[❌] Missing required tools: {', '.join(missing_tools)}")
        print("[💡] Install them using: apt install " + " ".join(missing_tools) + " -y")
        exit(1)
    else:
        print("[✔] All required tools are installed!\n")

# Run Nmap
def run_nmap(target):
    print("[+] Running Nmap Scan for Open Ports and Services...")
    os.system(f"nmap -sV -A {target} -oN nmap_scan.txt")

# Run Nikto
def run_nikto(target):
    print("[+] Running Nikto for Web Server Vulnerabilities...")
    os.system(f"nikto -h {target} -o nikto_report.txt")

# Run SQLMap
def run_sqlmap(target):
    print("[+] Running SQLMap for SQL Injection Testing...")
    os.system(f"sqlmap -u '{target}' --batch --dbs --output=sqlmap_report.txt")

# Run XSStrike
def run_xsstrike(target):
    print("[+] Running XSStrike for XSS Testing...")
    os.system(f"python3 xsstrike.py -u '{target}' --crawl")

# Run WFUZZ
def run_wfuzz(target):
    print("[+] Running WFUZZ for Brute-force Attack Testing...")
    os.system(f"wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 {target}/FUZZ")

# Run Open Redirect
def run_open_redirect(target):
    print("[+] Running Open Redirect Scanner...")
    os.system(f"python3 OpenRedirect.py -u '{target}'")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Hafiz OWASP Top 10 Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    target = args.url

    show_banner()
    check_required_tools()

    # Run scans in parallel threads
    threads = [
        threading.Thread(target=run_nmap, args=(target,)),
        threading.Thread(target=run_nikto, args=(target,)),
        threading.Thread(target=run_sqlmap, args=(target,)),
        threading.Thread(target=run_xsstrike, args=(target,)),
        threading.Thread(target=run_wfuzz, args=(target,)),
        threading.Thread(target=run_open_redirect, args=(target,))
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print("\n[✔] Scanning Completed! Reports are saved.")

if __name__ == "__main__":
    main()
