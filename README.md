For the common one:

Install the requests library:

pip install requests

Usage
Save the script as sql_injection.py.

python sql_injection.py <url> <param> <payload>

Example:
python sql_injection.py http://example.com/search query "' OR '1'='1"

Notes
Ensure you have permission to test the target web service.

This scripts is for educational purposes only. Unauthorized access to systems is illegal and unethical.
