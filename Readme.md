# 🛡️ OWASP Top 10 Vulnerability Scanner by Hafiz 🛡️

This is a Python-based tool designed to check for vulnerabilities based on the OWASP Top 10 list. It uses popular security testing tools like `sqlmap`, `nmap`, `nikto`, `hydra`, and others to detect common security issues in web applications.

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Results](#scan-results)
- [License](#license)

## Description
This script checks the following OWASP Top 10 vulnerabilities:
- **A01: Broken Access Control**
- **A02: Cryptographic Failures**
- **A03: Injection**
- **A04: Insecure Design**
- **A05: Security Misconfiguration**
- **A06: Vulnerable and Outdated Components**
- **A07: Identification and Authentication Failures**
- **A08: Software and Data Integrity Failures**
- **A09: Security Logging and Monitoring Failures**
- **A10: Server-Side Request Forgery**

It runs automated scans for each vulnerability category using relevant security testing tools.

## Features
- Scans for vulnerabilities from the OWASP Top 10 list.
- Uses popular tools like `sqlmap`, `nmap`, `nikto`, `hydra`, etc.
- Checks for tools installation and prompts to install missing tools only the first time.
- Customizable scan requests per second.
- Displays results of scans for vulnerabilities in an easy-to-read format.

## Requirements
Before running this script, ensure that the following tools are installed on your system:

- **sqlmap**
- **nmap**
- **nikto**
- **retire.js**
- **hydra**
- **john**
- **ossec**
- **git**

You can install these tools manually or follow the installation instructions below.

### Python Dependencies:
- `argparse`

Install the required Python package using the following command:

```bash
pip install argparse


Installation
Step 1: Clone the Repository

Clone this repository to your local machine.


git clone https://github.com/haiderali-43/owasp-top-10-scanner.git
cd owasp-top-10-scanner


Step 2: Install Required Tools

Make sure all the necessary tools are installed. You can install the missing tools manually using the instructions from their respective websites.

The script will notify you once about missing tools if you don't have them installed, and you can install them before running the script again.



Step 3: Install Python Packages

Install the argparse module required by the script.



pip install -r requirements.txt


Usage

To use the scanner, simply run the script with the target URL.


Usage

To use the scanner, simply run the script with the target URL.

python scanner.py -u http://example.com --rps 5

Arguments:

    -u or --url – Required: The target URL to scan.
    --rps – Optional: The number of requests per second for scanning (default: 5).

Example:

python scanner.py -u http://testwebsite.com --rps 10

First-time Setup:

When you run the script for the first time, it will check for the required tools (sqlmap, nmap, etc.). If any are missing, the script will notify you to install them. This check will only happen once, ensuring a smoother experience for subsequent runs.
Scan Results

The script will print out the scan results directly to your terminal. For each vulnerability category, the corresponding scan tool will be executed, and you will see output indicating whether the vulnerability was found or not.

    For each vulnerability type, the script will output whether the tool found an issue or if it was successful in checking.
    If a vulnerability is detected, the script will display a detailed message about it.

