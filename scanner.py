#!/usr/bin/env python3
"""
TCP/UDP Port Scanner Backend
Provides actual network scanning capabilities
"""

import socket
import ssl
import threading
import time
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.stop_scan = False
        self.results = []
        
    def scan_tcp_port(self, target, port, timeout=1):
        """Scan a single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False
    
    def scan_udp_port(self, target, port, timeout=2):
        """Scan a single UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send probe data
            probe_data = self.get_udp_probe(port)
            sock.sendto(probe_data, (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return port, True
            except socket.timeout:
                sock.close()
                return port, False
                
        except Exception:
            return port, False
    
    def get_udp_probe(self, port):
        """Get appropriate UDP probe for port"""
        probes = {
            53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',
            67: b'\x01\x01\x06\x00\x00\x00\x3d\x1d' + b'\x00' * 236,
            69: b'\x00\x01test.txt\x00netascii\x00',
            123: b'\x1b' + b'\x00' * 47,
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00',
        }
        return probes.get(port, b'\x00\x00\x00\x00')
    
    def check_ssl(self, target, port, timeout=3):
        """Check SSL/TLS on port"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            ssl_sock.connect((target, port))
            
            # Get certificate info
            cert = ssl_sock.getpeercert()
            cipher = ssl_sock.cipher()
            version = ssl_sock.version()
            
            ssl_sock.close()
            
            return {
                'version': version,
                'cipher': cipher[0] if cipher else 'Unknown',
                'certificate': {
                    'subject': dict(x[0] for x in cert.get('subject', [])) if cert else {},
                    'issuer': dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                    'not_after': cert.get('notAfter') if cert else None
                }
            }
            
        except Exception as e:
            return None
    
    def scan_ports(self, target, start_port, end_port, scan_tcp=True, scan_udp=False, 
                   check_ssl=False, timeout=1, max_threads=100):
        """Scan range of ports"""
        try:
            # Resolve target
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {'error': f'Failed to resolve {target}'}
        
        ports = list(range(start_port, end_port + 1))
        results = []
        
        # TCP Scanning
        if scan_tcp:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                tcp_futures = {
                    executor.submit(self.scan_tcp_port, target_ip, port, timeout): port 
                    for port in ports
                }
                
                for future in as_completed(tcp_futures):
                    if self.stop_scan:
                        break
                    
                    try:
                        port, is_open = future.result()
                        if is_open:
                            service = self.identify_service(port, 'tcp')
                            ssl_info = None
                            
                            if check_ssl and port in [443, 993, 995, 465, 587]:
                                ssl_info = self.check_ssl(target_ip, port)
                            
                            results.append({
                                'port': port,
                                'protocol': 'TCP',
                                'state': 'Open',
                                'service': service,
                                'ssl_info': ssl_info
                            })
                    except Exception:
                        pass
        
        # UDP Scanning (limited to common ports for performance)
        if scan_udp:
            common_udp = [53, 67, 69, 123, 161, 500, 514, 1900]
            udp_ports = [p for p in ports if p in common_udp]
            
            with ThreadPoolExecutor(max_workers=min(max_threads, 20)) as executor:
                udp_futures = {
                    executor.submit(self.scan_udp_port, target_ip, port, timeout * 2): port 
                    for port in udp_ports
                }
                
                for future in as_completed(udp_futures):
                    if self.stop_scan:
                        break
                    
                    try:
                        port, is_open = future.result()
                        if is_open:
                            service = self.identify_service(port, 'udp')
                            results.append({
                                'port': port,
                                'protocol': 'UDP',
                                'state': 'Open',
                                'service': service,
                                'ssl_info': None
                            })
                    except Exception:
                        pass
        
        return {
            'target': target,
            'results': results,
            'scan_time': time.time(),
            'total_scanned': len(ports)
        }
    
    def identify_service(self, port, protocol):
        """Identify service on port"""
        services = {
            # TCP Services
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            21: 'FTP', 1433: 'SQL Server', 3306: 'MySQL', 5432: 'PostgreSQL',
            3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8000: 'HTTP-Alt',
            
            # UDP Services  
            53: 'DNS', 67: 'DHCP', 69: 'TFTP', 123: 'NTP', 161: 'SNMP',
            500: 'ISAKMP', 514: 'Syslog', 1900: 'UPnP'
        }
        
        return services.get(port, f'Unknown-{protocol.upper()}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target> [start_port] [end_port]")
        sys.exit(1)
    
    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    
    scanner = NetworkScanner()
    print(f"Scanning {target}:{start_port}-{end_port}")
    
    results = scanner.scan_ports(target, start_port, end_port, 
                                scan_tcp=True, scan_udp=True, check_ssl=True)
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        return
    
    print(f"\nScan Results for {results['target']}:")
    print("=" * 40)
    
    if results['results']:
        for result in sorted(results['results'], key=lambda x: x['port']):
            ssl_text = ""
            if result['ssl_info']:
                ssl_text = f" (SSL: {result['ssl_info']['version']})"
            
            print(f"Port {result['port']}/{result['protocol']}: {result['service']}{ssl_text}")
    else:
        print("No open ports found.")
    
    print(f"\nScan completed. {len(results['results'])} open ports found.")

if __name__ == "__main__":
    main()