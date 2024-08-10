import requests
from bs4 import BeautifulSoup 
import nmap

def check_url(url):
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def sqli_test(url):
    payloads = ["'", "' OR '1'='1", '" OR "1"="1', " OR 1=1"] 
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = check_url(test_url)
        if response and "SQL syntax" in response.text:
            print(f"potential SQL injection vulnerability found at : {test_url}")
            return
    print("No SQL Injection vulnerability found.")


def xss_test(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}{payload}"
    response = check_url(test_url)
    if response :
        soup = BeautifulSoup(response.text , 'html.parser')
        if payload in str(soup):
            print (f"potential XSS vulnerability found at: {test_url}")
            return
    print ("No XSS vulnerability found.")


def header_test(response):
    security_headers = ["X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"]
    for header in security_headers:
        if header not in response.headers :
            print(f"Missing security header:{header}")
    print("Security headers check completed.")


def port_scan(domain):
    scanner=nmap.PortScanner()
    scanner.scan(domain , '1-1024')
    for host in scanner.all_hosts():
        print(f"Host : {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports :
                print(f"Port: {port} is open")


if __name__== "__main__":
    target_url = input("enter URL to scan :")
    domain= input("enter the domain for port scan:")

    response = check_url(target_url)
    if response:
        sqli_test(target_url)
        xss_test(target_url)
        header_test(response)
        port_scan(domain)