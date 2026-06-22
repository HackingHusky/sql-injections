import sys
import time
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def evaluate_target(url, param, payload):
    """
    Evaluates a web parameter for potential SQL injection vulnerabilities
    by checking for behavioral changes and time-delay responses.
    """
    # Define standard headers to look like a legitimate browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityTest/1.0"
    }

    # 1. Parse and rebuild the URL cleanly to handle parameters safely
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # 2. Establish a baseline (Normal behavior)
    try:
        baseline_start = time.time()
        baseline_response = requests.get(url, headers=headers, timeout=10)
        baseline_time = time.time() - baseline_start
        baseline_length = len(baseline_response.text)
    except requests.RequestException as e:
        print(f"[-] Error connecting to baseline URL: {e}")
        return

    # 3. Inject the payload into the specified parameter
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

    # 4. Execute the test request
    try:
        test_start = time.time()
        test_response = requests.get(target_url, headers=headers, timeout=15)
        test_time = time.time() - test_start
        test_length = len(test_response.text)
    except requests.RequestException as e:
        print(f"[-] Error connecting during test execution: {e}")
        return

    # 5. Analyze the results (Differential & Time Analysis)
    print(f"\n[*] Target Analysis for [{param}]:")
    print(f"    - Baseline: Size={baseline_length} bytes, Time={baseline_time:.2f}s, Status={baseline_response.status_code}")
    print(f"    - Test:     Size={test_length} bytes, Time={test_time:.2f}s, Status={test_response.status_code}")

    # Check for significant time delay (potential Time-Based Blind SQLi)
    if test_time > (baseline_time + 4) and test_time >= 4:
        print(f"[!] ALERT: Significant time delay detected ({test_time:.2f}s). Possible Time-Based Injection.")
    
    # Check for systemic changes in response content or HTTP status codes
    elif test_response.status_code != baseline_response.status_code:
        print(f"[!] WARNING: HTTP Status Code changed from {baseline_response.status_code} to {test_response.status_code}.")
        
    elif abs(test_length - baseline_length) > (baseline_length * 0.15): # 15% variance threshold
        print(f"[!] WARNING: Significant response body size variance detected. Possible Error/Boolean-Based Injection.")
        
    else:
        print("[-] Result: No obvious structural or timing anomalies detected.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sql_scan.py <url_with_or_without_params> <param_to_test> <payload>")
        print("Example: python sql_scan.py 'http://example.com' id '1 AND SLEEP(5)'")
        sys.exit(1)

    target_url = sys.argv[1]
    target_param = sys.argv[2]
    test_payload = sys.argv[3]

    evaluate_target(target_url, target_param, test_payload)
