"""
UDP Port Scanner Module
Handles UDP port scanning with various detection techniques
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class UDPScanner:
    def __init__(self):
        self.stop_scan = False
        
    def scan_port(self, target, port, timeout=2):
        """Scan a single UDP port"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send probe packet
            probe_data = self.get_probe_data(port)
            sock.sendto(probe_data, (target, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                return port, True  # Got response, port is likely open
                
            except socket.timeout:
                # No response - could be open but not responding, or filtered
                sock.close()
                
                # For UDP, we need additional checks
                # Try ICMP port unreachable detection
                return port, self.check_icmp_unreachable(target, port, timeout)
                
        except Exception:
            return port, False
    
    def get_probe_data(self, port):
        """Get appropriate probe data for specific UDP services"""
        # Common UDP service probes
        probes = {
            53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',  # DNS
            67: b'\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP
            69: b'\x00\x01test.txt\x00netascii\x00',  # TFTP
            123: b'\x1b' + b'\x00' * 47,  # NTP
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00',  # SNMP
            500: b'\x00\x00\x00\x00\x00\x00\x00\x00',  # ISAKMP
            514: b'<30>Test message',  # Syslog
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n',  # SSDP
        }
        
        return probes.get(port, b'\x00\x00\x00\x00')  # Default empty probe
    
    def check_icmp_unreachable(self, target, port, timeout):
        """
        Check for ICMP Port Unreachable messages (requires raw sockets in real implementation)
        This is a simplified version that uses heuristics
        """
        # In a real implementation, this would require raw sockets to capture ICMP
        # For this demo, we'll use a heuristic approach
        
        try:
            # Send multiple probes to increase chances of detection
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout / 2)
            
            for _ in range(2):
                probe_data = self.get_probe_data(port)
                sock.sendto(probe_data, (target, port))
                
                try:
                    # If we get any response, consider it potentially open
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    return True
                except socket.timeout:
                    continue
            
            sock.close()
            
            # No response received - could be closed or filtered
            # For common services, assume closed if no response
            common_udp_ports = [53, 67, 69, 123, 161, 500, 514, 1900]
            if port in common_udp_ports:
                return False
            else:
                # For uncommon ports, we can't be sure
                return False
                
        except Exception:
            return False
    
    def scan_ports(self, target, ports, timeout=2, max_threads=50, progress_callback=None):
        """Scan multiple UDP ports using threading"""
        results = []
        self.stop_scan = False
        
        # Resolve hostname to IP
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            raise Exception(f"Failed to resolve hostname: {target}")
        
        # UDP scanning is slower, so use fewer threads
        actual_threads = min(max_threads, 50)
        
        # Use ThreadPoolExecutor for controlled threading
        with ThreadPoolExecutor(max_workers=actual_threads) as executor:
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
    
    def advanced_udp_scan(self, target, port, timeout=2):
        """Perform advanced UDP scanning with service-specific probes"""
        results = {}
        
        try:
            # Try service-specific probe first
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            probe_data = self.get_service_probe(port)
            sock.sendto(probe_data, (target, port))
            
            try:
                response, addr = sock.recvfrom(4096)
                results['response'] = response
                results['open'] = True
                results['service_detected'] = self.analyze_udp_response(port, response)
                
            except socket.timeout:
                results['open'] = False
                results['response'] = None
                
            sock.close()
            
        except Exception as e:
            results['open'] = False
            results['error'] = str(e)
        
        return results
    
    def get_service_probe(self, port):
        """Get service-specific probe packets for better detection"""
        service_probes = {
            # DNS query for google.com
            53: b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01',
            
            # DHCP Discover
            67: b'\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
                b'\x00' * 192 + b'\x63\x82\x53\x63\x35\x01\x01\xff',
            
            # TFTP Read Request
            69: b'\x00\x01test.txt\x00octet\x00',
            
            # NTP request
            123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            
            # SNMP GetRequest
            161: b'\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00',
            
            # ISAKMP probe
            500: b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            
            # Syslog message
            514: b'<30>Jan  1 00:00:00 test: UDP port scan probe',
            
            # SSDP M-SEARCH
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n',
        }
        
        return service_probes.get(port, b'UDP_PROBE_TEST')
    
    def analyze_udp_response(self, port, response):
        """Analyze UDP response to identify service"""
        if not response:
            return None
        
        try:
            response_str = response.decode('utf-8', errors='ignore')
            response_hex = response.hex()
        except:
            response_str = ""
            response_hex = response.hex() if response else ""
        
        # Service-specific response analysis
        if port == 53:  # DNS
            if len(response) >= 12 and response[2] & 0x80:  # DNS response flag
                return "DNS Server"
        
        elif port == 67:  # DHCP
            if len(response) > 200 and response[0] == 0x02:  # DHCP offer
                return "DHCP Server"
        
        elif port == 69:  # TFTP
            if len(response) >= 4 and response[0:2] in [b'\x00\x03', b'\x00\x05']:
                return "TFTP Server"
        
        elif port == 123:  # NTP
            if len(response) >= 48:
                return "NTP Server"
        
        elif port == 161:  # SNMP
            if b'\x30' in response[:5]:  # ASN.1 sequence
                return "SNMP Agent"
        
        elif port == 514:  # Syslog
            return "Syslog Server"
        
        elif port == 1900:  # SSDP
            if b'HTTP/1.1' in response:
                return "UPnP/SSDP Service"
        
        return f"UDP Service (Port {port})"
    
    def get_common_udp_ports(self):
        """Return list of commonly scanned UDP ports"""
        return [
            53,    # DNS
            67,    # DHCP
            68,    # DHCP
            69,    # TFTP
            123,   # NTP
            135,   # RPC
            137,   # NetBIOS
            138,   # NetBIOS
            139,   # NetBIOS
            161,   # SNMP
            162,   # SNMP Trap
            445,   # SMB
            500,   # ISAKMP
            514,   # Syslog
            520,   # RIP
            623,   # IPMI
            631,   # IPP
            1434,  # SQL Server
            1900,  # UPnP
            4500,  # IPSec NAT-T
            5353,  # mDNS
        ]