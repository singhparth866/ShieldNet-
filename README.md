📌 Core Project What is ShieldNet?

ShieldNet is a unified web-based cybersecurity platform that integrates malware scanning, port scanning, breach detection, code protection, and an AI assistant into a single interface.

❓ What makes it different from existing tools?

Unlike tools like VirusTotal or Nmap that focus on a single function, ShieldNet combines multiple security tools into one platform with a unified dashboard and user-friendly interface.

❓ Future scope?

ML-based malware detection
Real-time threat intelligence integration
Mobile app version
Advanced enterprise security features
🦠 Malware Scanner

❓ What techniques are used?

Signature-based detection (known patterns)
Heuristic analysis (entropy, suspicious APIs, obfuscation)
❓ What is entropy analysis?

Entropy measures randomness (0–8). High entropy (>7.5) indicates packed/encrypted files — common in malware.

❓ Can it detect zero-day malware?

Not fully, but heuristic analysis helps identify suspicious behavior even without known signatures.

🔌 Port Scanner

❓ How does it work?

Uses TCP connection attempts (socket) to check if ports are open, closed, or filtered.

❓ Why multithreading?

Speeds up scanning by checking multiple ports simultaneously instead of sequentially.

❓ Why are some ports critical?

Ports like:

23 (Telnet) → unencrypted
445 (SMB) → ransomware target
🔓 Breach Detector

❓ How does k-anonymity work?

Email is hashed locally
Only first 5 characters sent
API returns possible matches
Local check confirms breach
Email is never exposed
❓ Why SHA-1?

Used only for lookup (not security), as HIBP database is indexed using SHA-1.

❓ What should users do after breach?

Change passwords
Enable 2FA
Avoid reuse
Use password manager
🔐 GuardCore

❓ What is code obfuscation?

Transforms readable code into unreadable form to prevent reverse engineering.

❓ What is virtualization-based protection? Code runs on a custom virtual machine using bytecode, making reverse engineering difficult.

❓ Can obfuscated code be reversed?

Yes, but it becomes highly complex and time-consuming.

⚙️ Architecture

❓ Why Flask?

Lightweight, flexible, and easier to manage compared to Django.

❓ Why AWS?

Provides scalability, reliability, and secure cloud deployment.

❓ Is port scanning legal?

Only on systems you own or have permission to scan.

❓ How is user privacy handled?

Emails are hashed (k-anonymity)
Files are not permanently stored
No sensitive data collection
🛡️ ShieldNet – Fortifying Your Digital Frontiers

ShieldNet is a cybersecurity-focused web application designed to provide essential tools for detecting, analyzing, and protecting against digital threats. It combines multiple security utilities into a single, user-friendly platform.

🌐 Features

🔍 Malware Scanner

A web-based tool that allows users to scan files, websites, or systems to detect malware, viruses, and other malicious threats.

🌐 Port Scanner

Scan systems, networks, or servers to identify open ports and potential vulnerabilities.

📧 Breach Detection

Check if an email address has been exposed in public data breaches and receive insights with recommended actions.

🛡️ GuardCore (Concept)

A proprietary security concept aimed at protecting users from exploitation using virtualization-based techniques.

🖼️ Screenshots

🏠 Home Page
<img width="1512" height="982" alt="Screenshot 2026-04-08 at 6 58 15 PM" src="https://github.com/user-attachments/assets/5555939d-39db-4e43-b316-7e5815c90250" />


📧 Breach Detection Tool
<img width="1512" height="982" alt="Screenshot 2026-04-08 at 7 00 31 PM" src="https://github.com/user-attachments/assets/e509e78c-0de4-431f-9437-b5e77e5be75f" />

⚙️ Services Section
<img width="1512" height="982" alt="Screenshot 2026-04-08 at 6 58 11 PM" src="https://github.com/user-attachments/assets/daa14e2b-6020-4e70-a98a-d34a1d617714" />

⚙️ Tech Stack

Frontend: HTML, CSS, JavaScript
Backend: Python
Framework: (Flask / Django — update this based on your project)
Other: APIs for breach detection (if used)
🚀 How to Run Locally

# Clone the repository
git clone https://github.com/your-username/shieldnet.git

# Navigate into the project
cd shieldnet

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
