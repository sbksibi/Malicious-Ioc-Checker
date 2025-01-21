import argparse
import requests
import time


# Function to check if an IP, hash, or URL is flagged as malicious by security vendors
def check_virustotal(input_value, input_type, api_key):
    url = f"https://www.virustotal.com/api/v3/{input_type}/{input_value}"
    headers = {'x-apikey': api_key}

    # Create a new session for each request
    with requests.Session() as session:
        response = session.get(url, headers=headers)

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
    elif len(value) in (32, 40, 64):  # MD5, SHA-1, or SHA-256
        return 'files'
    elif value.startswith(('http://', 'https://')):
        return 'urls'
    else:
        return None


# Main processing function
def process_inputs(input_file, api_keys_file, output_file):
    with open(input_file, 'r') as f:
        inputs = f.read().splitlines()

    with open(api_keys_file, 'r') as f:
        api_keys = f.read().splitlines()

    api_key_index = 0  # To rotate API keys

    with open(output_file, 'w') as out_file:
        for input_value in inputs:
            input_type = determine_type(input_value)

            if input_type is None:
                print(f"Unknown type for {input_value}, skipping.")
                continue

            # Use the current API key and rotate
            api_key = api_keys[api_key_index]
            result = check_virustotal(input_value, input_type, api_key)

            # Print both input and output (malicious only)
            print(f"Input: {input_value}")
            if "Malicious" in result:
                print(f"Output: {result}")
                out_file.write(result + '\n')
            else:
                print(f"Output: {result}")

            # Rotate API key and sleep to respect VirusTotal's rate limit
            api_key_index = (api_key_index + 1) % len(api_keys)
            time.sleep(1)  # Adjust the sleep time if needed for your API keys and limits


if __name__ == "__main__":
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Check inputs against VirusTotal API.")
    parser.add_argument("-f", "--file", required=True, help="Input file containing IPs, hashes, or URLs")
    parser.add_argument("-api", "--apikeys", required=True, help="File containing VirusTotal API keys (one per line)")
    parser.add_argument("-o", "--output", default="virustotal_malicious_results.txt",
                        help="Output file for malicious results (default: virustotal_malicious_results.txt)")

    args = parser.parse_args()

    # Call the processing function with parsed arguments
    process_inputs(args.file, args.apikeys, args.output)
