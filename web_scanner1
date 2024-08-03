import requests
import socket
import ssl
import urllib3
import time
from termcolor import colored
import subprocess
from tqdm import tqdm
import whois

urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def banner():
    print(" ")
    print(colored("  _____        ____  _____   _____ _   _ _______ ", 'red'))
    print(colored(" | ____|      / __ \/ ____| |_   _| \ | |__   __|", 'red'))
    print(colored(" |  _| ______| |  | | (___    | | |  \| |  | |  ", 'red'))
    print(colored(" |  _|/ __\_\_| |  | |\___ \   | | | . ` |  | |  ", 'red'))
    print(colored(" | |_\ \__/\_| |__| |____) | _| |_| |\  | _| |_ ", 'red'))
    print(colored(" \____/|_____|\____/|_____/|_____)_| \_|_____|", 'red'))
    print(" ")

def scan_status_code(url):
    urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        resp = requests.get(url, timeout=10, verify=False)
        print(colored("[+] Status Code: ", 'green') + str(resp.status_code))
    except Exception as e:
        print(colored("[+] Status Code: ", 'red') + str(e))

def scan_ssl_certificate(url):
    urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if "https" in url:
        try:
            context = ssl.create_default_context()
            cert = context.wrap_socket(socket.socket(), server_hostname=url.split("//")[-1].split("/")[0])
            cert.settimeout(10)
            cert.connect((url.split("//")[-1].split("/")[0], 443))
            certinfo = cert.getpeercert()
            print(colored("[+] SSL Certificate: ", 'green') + str(certinfo))
        except Exception as e:
            print(colored("[+] SSL Certificate: ", 'red') + str(e))
    else:
        print(colored("[+] SSL Certificate: ", 'green') + "This URL does not use HTTPS.")

def scan_http_headers(url):
    urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        req = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}, verify=False)
        headers = req.headers.items()
        print(colored("[+] HTTP Headers: ", 'green'))
        print(dict(headers))
    except Exception as e:
        print(colored("[+] HTTP Headers: ", 'red') + str(e))

def scan_tech_details(url):
    urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        for line in requests.get(url, timeout=10, verify=False, stream=True):
            print(line.decode('utf-8'), end='')
    except Exception as e:
        print(colored("[+] Tech Details: ", 'red') + str(e))

def scan_whois(host):
    try:
        w = whois.query(host)
        print(colored("[+] Whois Information: ", 'green'))
        print(str(w))
    except Exception as e:
        print(colored("[+] Whois Information: ", 'red') + str(e))

def scan_open_ports(host):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 144, 145, 146, 147, 149, 150, 151, 156, 161, 162, 179, 389, 443, 445, 512, 513, 514, 515, 520, 546, 547, 548, 554, 555, 556, 563, 636, 646, 993, 995, 1433, 1434, 1720, 1723, 1741, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3306, 3389, 5353, 5354, 5355, 5900, 6000, 6666, 6667, 6668, 6669, 6697, 8000, 8001, 8002, 8080, 8081, 8082, 8443, 8888, 9000, 9001, 9090, 9999]
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        print(colored("[+] Open Ports: ", 'green') + str(open_ports))
    except Exception as e:
        print(colored("[+] Open Ports: ", 'red') + str(e))

def scan_ssl_vulnerabilities(host):
    try:
        command = 'sslscan ' + host
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        print(result.decode())
    except subprocess.CalledProcessError as e:
        print(colored("[+] Error while scanning for SSL vulnerabilities: ", 'red') + str(e.output.decode()))

def scan_xss_vulnerabilities(url):
    try:
        command = 'xssfinder ' + url
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        print(result.decode())
    except subprocess.CalledProcessError as e:
        print(colored("[+] Error while scanning for XSS vulnerabilities: ", 'red') + str(e.output.decode()))

def scan_sql_injection_vulnerabilities(url):
    try:
        command = 'sqlmap -u ' + url
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        print(result.decode())
    except subprocess.CalledProcessError as e:
        print(colored("[+] Error while scanning for SQL injection vulnerabilities: ", 'red') + str(e.output.decode()))

def scan_web_application_vulnerabilities(url):
    try:
        command = 'nikto -h ' + url
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        print(result.decode())
    except subprocess.CalledProcessError as e:
        print(colored("[+] Error while scanning for web application vulnerabilities: ", 'red') + str(e.output.decode()))

def main():
    banner()
    url = input(colored("Enter the URL (HTTP or HTTPS): ", 'yellow'))
    scan_status_code(url)
    scan_ssl_certificate(url)
    scan_http_headers(url)
    host = url.split("//")[-1].split("/")[0]
    scan_tech_details(url)
    scan_whois(host)
    scan_open_ports(host)
    scan_ssl_vulnerabilities(host)
    scan_xss_vulnerabilities(url)
    scan_sql_injection_vulnerabilities(url)
    scan_web_application_vulnerabilities(url)

if __name__ == "__main__":
    main()
