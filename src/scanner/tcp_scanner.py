"""
TCP Port Scanner Module
Handles TCP port scanning with multi-threading support
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class TCPScanner:
    def __init__(self):
        self.stop_scan = False
        
    def scan_port(self, target, port, timeout=1):
        """Scan a single TCP port"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt connection
            result = sock.connect_ex((target, port))
            sock.close()
            
            return port, result == 0
            
        except socket.gaierror:
            # DNS resolution failed
            return port, False
        except Exception:
            return port, False
    
    def scan_ports(self, target, ports, timeout=1, max_threads=100, progress_callback=None):
        """Scan multiple TCP ports using threading"""
        results = []
        self.stop_scan = False
        
        # Resolve hostname to IP
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            raise Exception(f"Failed to resolve hostname: {target}")
        
        # Use ThreadPoolExecutor for controlled threading
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port, timeout): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                if self.stop_scan:
                    break
                    
                try:
                    port, is_open = future.result()
                    results.append((port, is_open))
                    
                    if progress_callback:
                        progress_callback()
                        
                except Exception as e:
                    port = future_to_port[future]
                    results.append((port, False))
        
        return results
    
    def stop(self):
        """Stop the current scan"""
        self.stop_scan = True
    
    def get_banner(self, target, port, timeout=3):
        """Attempt to grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send a basic HTTP request for web servers
            if port in [80, 8080, 8000, 3000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP servers usually send banner immediately
            elif port in [22, 23]:  # SSH, Telnet
                pass  # These services send banners on connection
            elif port == 25:  # SMTP
                pass  # SMTP servers send greeting
            else:
                # For other ports, try to trigger a response
                sock.send(b"\r\n")
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except:
            return None
    
    def advanced_scan(self, target, port, timeout=1):
        """Perform advanced TCP scanning techniques"""
        results = {}
        
        # Basic connect scan
        basic_result = self.scan_port(target, port, timeout)
        results['connect'] = basic_result[1]
        
        if results['connect']:
            # Try to get service banner
            banner = self.get_banner(target, port, timeout)
            results['banner'] = banner
            
            # Check for common service characteristics
            results['service_info'] = self.analyze_service(target, port, timeout)
        
        return results
    
    def analyze_service(self, target, port, timeout):
        """Analyze service running on the port"""
        service_info = {}
        
        try:
            if port == 22:  # SSH
                service_info = self.check_ssh_service(target, port, timeout)
            elif port in [80, 8080, 8000, 3000]:  # HTTP
                service_info = self.check_http_service(target, port, timeout)
            elif port == 443:  # HTTPS
                service_info = self.check_https_service(target, port, timeout)
            elif port == 21:  # FTP
                service_info = self.check_ftp_service(target, port, timeout)
            elif port == 25:  # SMTP
                service_info = self.check_smtp_service(target, port, timeout)
        except:
            pass
        
        return service_info
    
    def check_ssh_service(self, target, port, timeout):
        """Check SSH service details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return {'type': 'SSH', 'banner': banner}
        except:
            return {'type': 'SSH', 'banner': None}
    
    def check_http_service(self, target, port, timeout):
        """Check HTTP service details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse response headers
            lines = response.split('\r\n')
            status_line = lines[0] if lines else ""
            server_header = ""
            
            for line in lines[1:]:
                if line.lower().startswith('server:'):
                    server_header = line[7:].strip()
                    break
            
            return {
                'type': 'HTTP',
                'status': status_line,
                'server': server_header
            }
        except:
            return {'type': 'HTTP', 'status': None, 'server': None}
    
    def check_https_service(self, target, port, timeout):
        """Check HTTPS service details"""
        # This would be implemented with SSL checking
        # For now, return basic info
        return {'type': 'HTTPS', 'ssl': True}
    
    def check_ftp_service(self, target, port, timeout):
        """Check FTP service details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return {'type': 'FTP', 'banner': banner}
        except:
            return {'type': 'FTP', 'banner': None}
    
    def check_smtp_service(self, target, port, timeout):
        """Check SMTP service details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return {'type': 'SMTP', 'banner': banner}
        except:
            return {'type': 'SMTP', 'banner': None}