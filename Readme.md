# Hafiz Owasp Scanner

**Hafiz Owasp Scanner** is a Python script that helps in scanning a website for the top 10 OWASP vulnerabilities using popular security tools. The script checks if the required tools are installed and helps automate the scanning process.

---

## Features
- Scans for top 10 OWASP vulnerabilities.
- Checks if popular security tools like `nmap`, `dirb`, `nikto`, etc., are installed.
- Simple to use and can be easily modified for additional vulnerabilities.
  
## Vulnerabilities Covered
The script checks for vulnerabilities based on the OWASP Top 10, including but not limited to:
- Injection (SQLi)
- Cross-Site Scripting (XSS)
- Broken Authentication
- Sensitive Data Exposure
- XML External Entity (XXE)
- Security Misconfiguration
- Cross-Site Request Forgery (CSRF)
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring
- Insecure Deserialization

---

## Prerequisites

Make sure you have the following tools installed:
- `nmap`
- `nikto`
- `dirb`
- `wget`
- `curl`

The script checks if the required tools are installed. If any tool is missing, it will notify you.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Hafiz-Owasp-Scanner.git
