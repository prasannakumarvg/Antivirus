# Antivirus

Malware Scanner

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║   ██║██║██╔══██╗██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║██████╔╝██║   ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
  
This is a Python script that scans files for malware using VirusTotal API.

Description
This script allows you to scan individual files or directories for malware. It computes the MD5 hash of each file and checks it against the VirusTotal database to determine if it's malicious.

Requirements
Python 3.x
Requests library (pip install requests)
Colorama library (pip install colorama)

Usage

Clone the repository:

bash
git clone https://github.com/your_username/malware-scanner.git

Navigate to the directory:

bash
cd malware-scanner

Update your VirusTotal API key in the script:

bash
API_Key="YOUR_API_KEY_HERE"

Run the script:

bash
python malware_scanner.py

Follow the on-screen instructions to scan files or directories for malware.

Features
Scans individual files or directories.
Displays infected files, if any.
Deletes infected files upon user confirmation.

License
This project is licensed under the MIT License - see the MIT sLICENSE file for details.

Author
Prasannakumar
