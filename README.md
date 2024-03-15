# Antivirus


Malware Scanner

![Screenshot from 2024-03-16 07-02-39](https://github.com/prasannakumarvg/Antivirus/assets/123349921/fd1ccdbb-c6a0-4498-9921-7fa6db8d5731)


This Python script scans files for malware using the VirusTotal API.

Description

The Malware Scanner script allows users to scan individual files or entire directories for malware. It computes the MD5 hash of each file and checks it against the VirusTotal database to determine if it's malicious. If a file is identified as malware, the script provides options to delete the infected file(s) upon user confirmation.

Requirements

Python 3.x
Requests library (pip install requests)
Colorama library (pip install colorama)

Usage

Clone the repository:

    > git clone https://github.com/your_username/malware-scanner.git
        
Navigate to the directory:
    
    > cd malware-scanner
    > Update your VirusTotal API key in the script:

Add Your VirusTotal API Key:

    > API_Key="YOUR_API_KEY_HERE"

Run the script:

    > python malware_scanner.py
    
Follow the on-screen instructions to scan files or directories for malware.

Features

Scans individual files or directories.
Displays infected files, if any.
Provides options to delete infected files upon user confirmation.


License

This project is licensed under the MIT License - see the LICENSE file for details.

Author

Prasannakumar
