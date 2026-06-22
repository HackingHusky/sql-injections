import sys
import os
import time
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def evaluate_wordlist(url, param, wordlist_path):
    """
    Automates the evaluation of a target web parameter against a list of 
    test payloads provided in a local text file.
    """
    # 1. Validate existence of the wordlist file
    if not os.path.isfile(wordlist_path):
        print(f"[-] Error: Wordlist file not found at '{wordlist_path}'")
        return

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityTest/1.0"
    }

    # 2. Parse the base URL structure
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # 3. Establish a single Baseline before iterating
    print("[*] Establishing system baseline behavior...")
    try:
        baseline_start = time.time()
        baseline_response = requests.get(url, headers=headers, timeout=10)
        baseline_time = time.time() - baseline_start
        baseline_length = len(baseline_response.text)
        print(f"[+] Baseline Established: Size={baseline_length} bytes, Time={baseline_time:.2f}s, Status={baseline_response.status_code}\n")
    except requests.RequestException as e:
        print(f"[-] Critical Error connecting to baseline URL: {e}")
        return

    # 4. Process the wordlist
    findings_count = 0
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
        payloads = [line.strip() for line in file if line.strip()]

    print(f"[*] Starting iteration over {len(payloads)} payloads against parameter [{param}]...")
    print("-" * 80)

    for idx, payload in enumerate(payloads, start=1):
        # Inject current payload into the parameter dictionary
        query_params[param] = [payload]
        new_query = urlencode(query_params, doseq=True)
        target_url = urlunparse((
            parsed_url.scheme, 
            parsed_url.netloc, 
            parsed_url.path, 
            parsed_url.params, 
            new_query, 
            parsed_url.fragment
        ))

        try:
            test_start = time.time()
            test_response = requests.get(target_url, headers=headers, timeout=15)
            test_time = time.time() - test_start
            test_length = len(test_response.text)
        except requests.RequestException as e:
            print(f"[-] [{idx}/{len(payloads)}] Connection error with payload '{payload}': {e}")
            continue

        # 5. Evaluate behavioral anomalies compared to baseline
        is_anomalous = False
        anomaly_reason = ""

        # Time-based tracking
        if test_time > (baseline_time + 4) and test_time >= 4:
            is_anomalous = True
            anomaly_reason = f"Significant time delay detected ({test_time:.2f}s vs baseline {baseline_time:.2f}s)"
        
        # Status code tracking
        elif test_response.status_code != baseline_response.status_code:
            is_anomalous = True
            anomaly_reason = f"HTTP Status Code changed from {baseline_response.status_code} to {test_response.status_code}"
            
        # Size variance tracking (15% threshold rule)
        elif abs(test_length - baseline_length) > (baseline_length * 0.15):
            is_anomalous = True
            anomaly_reason = f"Significant response size variance (Size: {test_length} bytes vs baseline {baseline_length} bytes)"

        # Reporting anomalies
        if is_anomalous:
            findings_count += 1
            print(f"[!] FLAG DETECTED [{idx}/{len(payloads)}]")
            print(f"    - Payload: {payload}")
            print(f"    - Reason:  {anomaly_reason}")
            print("-" * 80)
        else:
            # Print periodic standard progress markers every 10 payloads to show script activity
            if idx % 10 == 0 or idx == len(payloads):
                print(f"[*] Progress: Completed {idx}/{len(payloads)} payloads...")

    print(f"\n[*] Automation Completed. Total anomalies flagged: {findings_count}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sql_wordlist_scanner.py <url> <param_to_test> <path_to_wordlist>")
        print("Example: python sql_wordlist_scanner.py 'http://example.com' id 'my_payloads.txt'")
        sys.exit(1)

    target_url = sys.argv[1]
    target_param = sys.argv[2]
    wordlist_file = sys.argv[3]

    evaluate_wordlist(target_url, target_param, wordlist_file)
