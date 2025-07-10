import time
import requests
import socket
import builtwith
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import matplotlib

# Set Matplotlib backend
matplotlib.use('TkAgg')

# Random user-agent to bypass bot detection
try:
    from fake_useragent import UserAgent
    ua = UserAgent()
    user_agent = ua.random
except:
    user_agent = "Mozilla/5.0"

HEADERS = {
    "User-Agent": user_agent,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.google.com/",
    "DNT": "1",
    "Connection": "keep-alive"
}

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def check_dns_registration(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def check_website_access(url):
    session = requests.Session()
    session.headers.update(HEADERS)
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        if response.status_code in [400, 403, 429]:
            return False, f"Blocked - HTTP {response.status_code}"
        elif response.status_code < 400:
            return True, None
        else:
            return False, f"HTTP Error {response.status_code}"
    except requests.ConnectionError:
        return False, "Connection error - Server might be down."
    except requests.Timeout:
        return False, "Timeout error - Slow server response."
    except requests.RequestException as e:
        return False, f"Unknown error - {str(e)}"

def scan_headers(url):
    try:
        headers = requests.get(url, headers=HEADERS).headers
    except requests.RequestException:
        return 0

    security_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]
    missing = sum(1 for h in security_headers if h not in headers)
    return missing * 10

def scan_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        res = requests.get(url, params={"id": payload}, headers=HEADERS)
        if "mysql" in res.text.lower() or "syntax error" in res.text.lower():
            return 80
    except requests.RequestException:
        pass
    return 0

def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        res = requests.get(url, params={"q": payload}, headers=HEADERS)
        if payload in res.text:
            return 70
    except requests.RequestException:
        pass
    return 0

def scan_directory_traversal(url):
    payload = "../../etc/passwd"
    try:
        res = requests.get(url, params={"file": payload}, headers=HEADERS)
        if "root:x:" in res.text:
            return 90
    except requests.RequestException:
        pass
    return 0

def scan_open_redirect(url):
    payload = "http://evil.com"
    try:
        res = requests.get(url, params={"redirect": payload}, headers=HEADERS, allow_redirects=False)
        if res.status_code in [301, 302] and "evil.com" in res.headers.get("Location", ""):
            return 50
    except requests.RequestException:
        pass
    return 0

def check_insecure_protocol(url):
    return 30 if urlparse(url).scheme == "http" else 0

def scan_login_form(url):
    try:
        res = requests.get(url, headers=HEADERS)
        return 40 if "password" in res.text and "login" in res.text else 0
    except requests.RequestException:
        return 0

def scan_website(url):
    print(f"\n🔍 Checking website: {url}")

    if not is_valid_url(url):
        return None, "Invalid URL format."

    domain = urlparse(url).netloc
    if not check_dns_registration(domain):
        return None, "Domain not registered or DNS error."

    website_ok, error_msg = check_website_access(url)
    if not website_ok:
        return None, error_msg

    print("✅ Website is accessible. Scanning for vulnerabilities...")

    vulnerabilities = {
        "Missing Headers": scan_headers(url),
        "SQL Injection": scan_sql_injection(url),
        "XSS": scan_xss(url),
        "Directory Traversal": scan_directory_traversal(url),
        "Open Redirect": scan_open_redirect(url),
        "Insecure Protocol": check_insecure_protocol(url),
        "Weak Login Form": scan_login_form(url)
    }

    total_risk_score = min(100, sum(vulnerabilities.values()))
    return vulnerabilities, total_risk_score

def plot_vulnerabilities(vulnerabilities, total_risk_score):
    labels = list(vulnerabilities.keys())
    values = list(vulnerabilities.values())
    colors = ["red" if v >= 80 else "orange" if v >= 50 else "yellow" if v >= 30 else "green" for v in values]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color=colors)
    plt.xlabel("Vulnerability Type")
    plt.ylabel("Risk Level (%)")
    plt.title(f"Security Scan Results (Risk Score: {total_risk_score}%)")
    plt.xticks(rotation=45)
    plt.ylim(0, 100)
    plt.tight_layout()
    plt.show()

def get_website_technologies(url):
    print("\n🔧 Detecting technologies used on the website...")
    try:
        tech_info = builtwith.builtwith(url)
        if tech_info:
            for key, val in tech_info.items():
                print(f"{key}: {', '.join(val)}")
        else:
            print("No technology info found.")
    except Exception as e:
        print(f"Technology detection failed: {e}")

# ✅ MAIN PROGRAM STARTS HERE
if __name__ == "__main__":

    while True:
        target_url = input("\nEnter website URL to scan (or 'q' to quit): ").strip()
        if target_url.lower() in ['q', 'quit']:
            print("👋 Exiting scanner. Bye!")
            break

        if not target_url.startswith("http"):
            target_url = "https://" + target_url

        results, message = scan_website(target_url)
        if results is None:
            print(f"❌ Scan failed: {message}")
        else:
            print("\n✅ Scan Results:")
            for vuln, score in results.items():
                status = "Detected" if score > 0 else "Not Detected"
                print(f"- {vuln}: {status} (Risk Score: {score}%)")

            print(f"\n🔒 Total Website Risk Score: {message}%")
            plot_vulnerabilities(results, message)

        get_website_technologies(target_url)
        print("\n" + "-" * 60)
