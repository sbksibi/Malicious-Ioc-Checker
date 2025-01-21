# Malicious IP and Hash Checker

This Python script checks IP addresses and file hashes (MD5, SHA256) against the VirusTotal database to identify malicious activity. The results are saved to a file and also displayed in the terminal.

## Features
- Reads IPs and file hashes from an input file (`input.txt`).
- Verifies entries using the VirusTotal API.
- Outputs malicious results to a file named `virustotal_malicious_results.txt`.
- Displays results in the terminal for quick viewing.

## Requirements
- Python 3.x
- VirusTotal API key

## Setup

1. Clone the repository:
   ```bash
   https://github.com/sbksibi/Malicious-Ioc-Checker.git
   cd Malicious-Ioc-Checker
2. Add your API key in the MaliciousChecker.py file by replacing your_virustotal_api_key with your actual key.
3. ```bash
    pip install requests

## RUN

1. input.txt:
    ```bash
    192.168.0.1
    8.8.8.8
    d41d8cd98f00b204e9800998ecf8427e
2. Run the script using the following command:
 ```bash
   python3 MaliciousChecker.py -f input.txt -api apikeys.txt
 ```

## Output Example

![Screenshot 2024-12-11 163823](https://github.com/user-attachments/assets/ea32ffde-6493-41b6-ba38-161d9ca9e0cb)

