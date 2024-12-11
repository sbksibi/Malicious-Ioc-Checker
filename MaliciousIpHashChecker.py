import requests
import time

# List of VirusTotal API keys (rotate between them to avoid rate limits)
API_KEYS = [
    'API-KEY',
    'API-KEY',
    'API-KEY',
    # Add more keys as needed
]

# Function to check if an IP, hash, or URL is flagged as malicious by security vendors
def check_virustotal(input_value, input_type, api_key):
    url = f"https://www.virustotal.com/api/v3/{input_type}/{input_value}"
    headers = {'x-apikey': api_key}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 401:
        return f"{input_value} - Error {response.status_code} (Unauthorized: Check API Key)"
    elif response.status_code == 200:
        result = response.json()
        
        if 'data' in result and 'attributes' in result['data']:
            analysis_stats = result['data']['attributes']['last_analysis_stats']
            if analysis_stats['malicious'] > 0:
                return f"{input_value} - Malicious (Flagged by {analysis_stats['malicious']} vendors)"
            else:
                return f"{input_value} - Clean (No malicious flags)"
        else:
            return f"{input_value} - No data available"
    else:
        return f"{input_value} - Error {response.status_code}"

# Function to determine the type of input (IP, hash, or URL)
def determine_type(value):
    if value.count('.') == 3 and all(part.isdigit() for part in value.split('.')):
        return 'ip_addresses'
    elif len(value) == 64 or len(value) == 40:  # Assuming hash (SHA-256 or SHA-1)
        return 'files'
    elif value.startswith(('http://', 'https://')):
        return 'urls'
    else:
        return None
    
def process_inputs(file_path, output_file):
    with open(file_path, 'r') as f:
        inputs = f.read().splitlines()

    api_key_index = 0  # To rotate API keys

    with open(output_file, 'w') as out_file:
        for input_value in inputs:
            input_type = determine_type(input_value)

            if input_type is None:
                print(f"Unknown type for {input_value}, skipping.")
                continue

            # Use the current API key and rotate
            api_key = API_KEYS[api_key_index]
            result = check_virustotal(input_value, input_type, api_key)

            # Print both input and output (malicious only)
            print(f"Input: {input_value}")
            if "Malicious" in result:
                print(f"Output: {result}")
                out_file.write(result + '\n')
            else:
                print(f"Output: {result}")

            # Rotate API key and sleep to respect VirusTotal's rate limit
            api_key_index = (api_key_index + 1) % len(API_KEYS)
            time.sleep(1)  # Adjust the sleep time if needed for your API keys and limits

# File paths
input_file = "input.txt"  # Replace with your file containing IPs, hashes, or URLs
output_file = "virustotal_malicious_results.txt"  # The output file where malicious results will be saved


process_inputs(input_file, output_file)
