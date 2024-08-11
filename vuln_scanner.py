import requests
from bs4 import BeautifulSoup
import nmap
import threading

def check_url(url):
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def sqli_test(url):
    payloads = ["'", "' OR '1'='1", '" OR "1"="1', " OR 1=1", "--", ";", "' AND '1'='1"]
    error_messages = ["SQL syntax", "mysql_fetch_array", "You have an error in your SQL syntax", "Warning: mysql", "Unclosed quotation mark"]
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = check_url(test_url)
        if response:
            for error in error_messages:
                if error in response.text:
                    print(f"Potential SQL injection vulnerability found at: {test_url}")
                    return
    print("No SQL Injection vulnerability found.")

def xss_test(url):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<body onload=alert('XSS')>"]
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = check_url(test_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            if payload in str(soup):
                print(f"Potential XSS vulnerability found at: {test_url}")
                return
    print("No XSS vulnerability found.")

def csrf_test(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        if not form.find('input', {'type': 'hidden', 'name': 'csrf'}):
            print("Potential CSRF vulnerability: No CSRF token found in form.")
            return
    print("No CSRF vulnerability found.")

def header_test(response):
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'"
    }
    
    for header, recommended_value in security_headers.items():
        if header not in response.headers:
            print(f"Missing security header: {header}")
        elif recommended_value not in response.headers[header]:
            print(f"Weak security header: {header} - Expected value: {recommended_value}")
    print("Security headers check completed.")

def path_traversal_test(url):
    payloads = ["../../../../etc/passwd", "../../../../C:/Windows/win.ini"]
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = check_url(test_url)
        if response and ("root:x" in response.text or "[extensions]" in response.text):
            print(f"Potential Path Traversal vulnerability found at: {test_url}")
            return
    print("No Path Traversal vulnerability found.")

def port_scan(domain):
    scanner = nmap.PortScanner()
    scanner.scan(domain, '1-1024', '-sV')
    
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]['name']
                print(f"Port: {port} is open (Service: {service})")

if __name__ == "__main__":
    target_url = input("Enter URL to scan: ")
    domain = input("Enter the domain for port scan: ")
    
    response = check_url(target_url)
    if response:
        sqli_test(target_url)
        xss_test(target_url)
        csrf_test(response)
        header_test(response)
        path_traversal_test(target_url)
        port_scan(domain)

