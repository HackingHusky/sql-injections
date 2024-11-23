import requests
import sys

def sql_injection(url, param, payload):
    target_url = f"{url}?{param}={payload}"
    response = requests.get(target_url)
    
    if "error" not in response.text.lower():
        print(f"Potential SQL Injection vulnerability found with payload: {payload}")
    else:
        print(f"No vulnerability found with payload: {payload}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sql_injection.py <url> <param> <payload>")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]
    payload = sys.argv[3]

    sql_injection(url, param, payload)
