import requests
from bs4 import BeautifulSoup
import nmap
import ssl
import socket


def check_open_ports(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-Pn')
    open_ports = []
    for proto in nm[target].all_protocols():
        open_ports.extend(nm[target][proto].keys())
    return open_ports


def check_ssl_tls(target):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return f"SSL/TLS check failed: {str(e)}"


def check_outdated_software(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers
        outdated_info = {
            "Server": headers.get("Server", "Unknown"),
            "X-Powered-By": headers.get("X-Powered-By", "Unknown")
        }
        return outdated_info
    except requests.exceptions.RequestException as e:
        return f"Error checking software versions: {str(e)}"


def generate_report(target, port_scan, ssl_tls, outdated_software):
    report = f"--- Vulnerability Report for {target} ---\n\n"
    
    report += "1. Open Ports:\n"
    if port_scan:
        report += f"Open ports: {', '.join(map(str, port_scan))}\n"
    else:
        report += "No open ports detected or scan failed.\n"
    
    report += "\n2. SSL/TLS Configuration:\n"
    if isinstance(ssl_tls, dict):
        report += "SSL Certificate Details:\n"
        for key, value in ssl_tls.items():
            report += f"  {key}: {value}\n"
    else:
        report += f"SSL/TLS Status: {ssl_tls}\n"
    
    report += "\n3. Outdated Software:\n"
    if isinstance(outdated_software, dict):
        for key, value in outdated_software.items():
            report += f"  {key}: {value}\n"
    else:
        report += f"Outdated Software Status: {outdated_software}\n"
    
    return report


if __name__ == "__main__":
    target_ip = input("Enter the target IP or domain: ").strip()
    url = f"http://{target_ip}"

    print("Scanning for open ports...")
    open_ports = check_open_ports(target_ip)

    print("Checking SSL/TLS configurations...")
    ssl_tls_info = check_ssl_tls(target_ip)

    print("Checking for outdated software versions...")
    outdated_software_info = check_outdated_software(url)

    print("Generating report...")
    report = generate_report(target_ip, open_ports, ssl_tls_info, outdated_software_info)

    print(report)
    with open(f"{target_ip}_vulnerability_report.txt", "w") as file:
        file.write(report)

    print(f"Vulnerability report saved as {target_ip}_vulnerability_report.txt")
