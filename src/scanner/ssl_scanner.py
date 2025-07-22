"""
SSL/TLS Scanner Module
Handles SSL/TLS detection and certificate analysis
"""

import socket
import ssl
import threading
from datetime import datetime
import json

class SSLScanner:
    def __init__(self):
        self.timeout = 5
        
    def check_ssl(self, target, port, timeout=5):
        """Check if port supports SSL/TLS"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Wrap socket with SSL
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            ssl_sock.connect((target, port))
            
            # Get certificate info
            cert_info = self.get_certificate_info(ssl_sock)
            
            ssl_sock.close()
            return cert_info
            
        except ssl.SSLError as e:
            return f"SSL Error: {str(e)}"
        except socket.timeout:
            return "SSL Connection Timeout"
        except Exception as e:
            return None
    
    def get_certificate_info(self, ssl_socket):
        """Extract certificate information"""
        try:
            cert = ssl_socket.getpeercert()
            
            if not cert:
                return "No certificate available"
            
            # Extract key information
            info = {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'version': cert.get('version'),
                'serial_number': cert.get('serialNumber'),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter'),
                'signature_algorithm': cert.get('signatureAlgorithm'),
            }
            
            # Check if certificate is expired
            not_after = cert.get('notAfter')
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    is_expired = expiry_date < datetime.now()
                    days_until_expiry = (expiry_date - datetime.now()).days
                    info['expired'] = is_expired
                    info['days_until_expiry'] = days_until_expiry
                except:
                    pass
            
            # Get subject alternative names
            san = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    san.append(ext[1])
            info['subject_alt_names'] = san
            
            return self.format_certificate_info(info)
            
        except Exception as e:
            return f"Certificate analysis error: {str(e)}"
    
    def format_certificate_info(self, info):
        """Format certificate information for display"""
        try:
            lines = []
            
            # Subject information
            subject = info.get('subject', {})
            if 'commonName' in subject:
                lines.append(f"Common Name: {subject['commonName']}")
            if 'organizationName' in subject:
                lines.append(f"Organization: {subject['organizationName']}")
            
            # Issuer information
            issuer = info.get('issuer', {})
            if 'commonName' in issuer:
                lines.append(f"Issued by: {issuer['commonName']}")
            
            # Validity period
            if 'not_before' in info:
                lines.append(f"Valid from: {info['not_before']}")
            if 'not_after' in info:
                lines.append(f"Valid until: {info['not_after']}")
            
            # Expiration status
            if 'expired' in info:
                if info['expired']:
                    lines.append("Status: EXPIRED")
                else:
                    days = info.get('days_until_expiry', 0)
                    if days < 30:
                        lines.append(f"Status: Expires in {days} days (WARNING)")
                    else:
                        lines.append(f"Status: Valid ({days} days remaining)")
            
            # Subject Alternative Names
            san = info.get('subject_alt_names', [])
            if san:
                lines.append(f"Alt Names: {', '.join(san[:3])}{'...' if len(san) > 3 else ''}")
            
            # Signature algorithm
            if 'signature_algorithm' in info:
                lines.append(f"Signature: {info['signature_algorithm']}")
            
            return '\n    '.join(lines)
            
        except Exception as e:
            return f"Certificate formatting error: {str(e)}"
    
    def check_ssl_protocols(self, target, port, timeout=5):
        """Check supported SSL/TLS protocols"""
        protocols = {
            'SSLv23': ssl.PROTOCOL_SSLv23,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Add TLS 1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
            protocols['TLSv1.3'] = ssl.PROTOCOL_TLS_CLIENT
        
        supported_protocols = []
        
        for protocol_name, protocol_constant in protocols.items():
            try:
                context = ssl.SSLContext(protocol_constant)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                ssl_sock = context.wrap_socket(sock)
                ssl_sock.connect((target, port))
                
                # Get the actual protocol used
                actual_protocol = ssl_sock.version()
                ssl_sock.close()
                
                if actual_protocol:
                    supported_protocols.append(actual_protocol)
                    
            except Exception:
                continue
        
        return list(set(supported_protocols))  # Remove duplicates
    
    def check_ssl_ciphers(self, target, port, timeout=5):
        """Check supported SSL/TLS cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            ssl_sock = context.wrap_socket(sock)
            ssl_sock.connect((target, port))
            
            cipher_info = ssl_sock.cipher()
            ssl_sock.close()
            
            if cipher_info:
                return {
                    'cipher_name': cipher_info[0],
                    'protocol_version': cipher_info[1],
                    'secret_bits': cipher_info[2]
                }
            
        except Exception as e:
            return None
        
        return None
    
    def comprehensive_ssl_scan(self, target, port, timeout=5):
        """Perform comprehensive SSL/TLS analysis"""
        results = {
            'ssl_supported': False,
            'certificate_info': None,
            'protocols': [],
            'cipher_info': None,
            'vulnerabilities': []
        }
        
        try:
            # Basic SSL check
            cert_info = self.check_ssl(target, port, timeout)
            if cert_info and not cert_info.startswith('SSL Error'):
                results['ssl_supported'] = True
                results['certificate_info'] = cert_info
                
                # Check protocols
                results['protocols'] = self.check_ssl_protocols(target, port, timeout)
                
                # Check cipher suites
                results['cipher_info'] = self.check_ssl_ciphers(target, port, timeout)
                
                # Check for common vulnerabilities
                results['vulnerabilities'] = self.check_ssl_vulnerabilities(target, port, timeout)
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_ssl_vulnerabilities(self, target, port, timeout=5):
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for SSLv2/SSLv3 support (deprecated and vulnerable)
            for protocol_name, protocol in [('SSLv2', 'SSLv2'), ('SSLv3', ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None)]:
                if protocol:
                    try:
                        if protocol == 'SSLv2':
                            # SSLv2 is not supported in modern Python SSL modules
                            continue
                        
                        context = ssl.SSLContext(protocol)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        
                        ssl_sock = context.wrap_socket(sock)
                        ssl_sock.connect((target, port))
                        ssl_sock.close()
                        
                        vulnerabilities.append(f"{protocol_name} supported (VULNERABLE)")
                        
                    except Exception:
                        # Good - protocol not supported
                        pass
            
            # Check for weak ciphers
            cipher_info = self.check_ssl_ciphers(target, port, timeout)
            if cipher_info:
                cipher_name = cipher_info.get('cipher_name', '').upper()
                secret_bits = cipher_info.get('secret_bits', 0)
                
                # Check for weak encryption
                if secret_bits < 128:
                    vulnerabilities.append(f"Weak encryption: {secret_bits} bits")
                
                # Check for deprecated ciphers
                weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
                for weak in weak_ciphers:
                    if weak in cipher_name:
                        vulnerabilities.append(f"Weak cipher: {weak}")
            
            # Check certificate expiration
            if hasattr(self, 'last_cert_info') and self.last_cert_info:
                if 'expired' in self.last_cert_info and self.last_cert_info['expired']:
                    vulnerabilities.append("Certificate expired")
                elif 'days_until_expiry' in self.last_cert_info:
                    days = self.last_cert_info['days_until_expiry']
                    if days < 30:
                        vulnerabilities.append(f"Certificate expires soon ({days} days)")
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def scan_ssl_ports(self, target, ports, timeout=5, progress_callback=None):
        """Scan multiple ports for SSL/TLS support"""
        results = []
        
        for port in ports:
            if progress_callback:
                progress_callback()
            
            ssl_info = self.comprehensive_ssl_scan(target, port, timeout)
            if ssl_info['ssl_supported']:
                results.append((port, ssl_info))
        
        return results