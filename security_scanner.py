import requests
import ssl
import socket
import json
from datetime import datetime
from urllib.parse import urljoin
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

class SecurityScanner:
    def __init__(self, target_url):
        """Initialize the security scanner with a target URL."""
        self.target_url = target_url
        self.findings = []
        self.headers = {
            'User-Agent': 'Security-Audit-Script/1.0',
        }

    def check_ssl_tls(self):
        """Check SSL/TLS configuration of the target."""
        try:
            hostname = self.target_url.replace('https://', '').split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                    if not_after < datetime.now():
                        self.findings.append({
                            'type': 'ssl_expired',
                            'severity': 'HIGH',
                            'description': 'SSL certificate has expired'
                        })

                    # Check SSL version
                    version = ssock.version()
                    if version == 'TLSv1' or version == 'TLSv1.1':
                        self.findings.append({
                            'type': 'weak_ssl_version',
                            'severity': 'MEDIUM',
                            'description': f'Weak SSL/TLS version detected: {version}'
                        })

        except Exception as e:
            self.findings.append({
                'type': 'ssl_error',
                'severity': 'HIGH',
                'description': f'SSL/TLS connection error: {str(e)}'
            })

    def check_security_headers(self):
        """Check for important security headers."""
        try:
            response = requests.get(self.target_url, headers=self.headers, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'Content-Security-Policy': 'Missing Content Security Policy'
            }

            for header, message in security_headers.items():
                if header not in headers:
                    self.findings.append({
                        'type': 'missing_security_header',
                        'severity': 'MEDIUM',
                        'description': message
                    })

        except requests.exceptions.RequestException as e:
            self.findings.append({
                'type': 'request_error',
                'severity': 'INFO',
                'description': f'Error checking security headers: {str(e)}'
            })

    def check_open_ports(self, common_ports=[80, 443, 8080, 8443]):
        """Check for commonly exposed ports."""
        hostname = self.target_url.replace('https://', '').replace('http://', '').split('/')[0]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    self.findings.append({
                        'type': 'open_port',
                        'severity': 'LOW',
                        'description': f'Port {port} is open'
                    })
                sock.close()
            except Exception:
                continue

    def check_information_disclosure(self):
        """Check for common information disclosure issues."""
        common_paths = [
            '/robots.txt',
            '/.git/',
            '/.env',
            '/backup/',
            '/phpinfo.php'
        ]

        for path in common_paths:
            try:
                url = urljoin(self.target_url, path)
                response = requests.get(url, headers=self.headers, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'information_disclosure',
                        'severity': 'MEDIUM',
                        'description': f'Potentially sensitive file/directory found: {path}'
                    })
            except requests.exceptions.RequestException:
                continue

    def generate_report(self):
        """Generate a JSON report of all findings."""
        report = {
            'scan_target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'high_severity': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium_severity': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low_severity': len([f for f in self.findings if f['severity'] == 'LOW'])
            }
        }
        return json.dumps(report, indent=4)

    def run_scan(self):
        """Run all security checks."""
        print(f"Starting security scan of {self.target_url}")
        
        self.check_ssl_tls()
        self.check_security_headers()
        self.check_open_ports()
        self.check_information_disclosure()
        
        return self.generate_report()

def main():
    """Main function to run the security scanner."""
    print("Web Application Security Scanner")
    print("-" * 30)
    
    # Get target URL from user input
    while True:
        target_url = input("Enter the domain or IP address to scan (e.g., https://example.com): ").strip()
        
        # Add https:// if not present
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Basic URL validation
        try:
            requests.get(target_url, verify=False, timeout=5)
            break
        except requests.exceptions.RequestException:
            print("Error: Unable to connect to the specified domain. Please check the URL and try again.")
    
    # Generate output filename based on domain and timestamp
    domain_name = target_url.replace('https://', '').replace('http://', '').split('/')[0]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"security_report.json"
    
    # Run the scan
    scanner = SecurityScanner(target_url)
    report = scanner.run_scan()
    
    # Save the report
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"\nScan complete. Report saved to {output_file}")

if __name__ == "__main__":
    main()
