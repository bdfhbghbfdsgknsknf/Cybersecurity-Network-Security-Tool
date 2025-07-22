"""
Service Detection Module
Identifies services running on specific ports
"""

class ServiceDetector:
    def __init__(self):
        self.tcp_services = self.load_tcp_services()
        self.udp_services = self.load_udp_services()
        
    def load_tcp_services(self):
        """Load TCP service definitions"""
        return {
            # Web Services
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP Alternate",
            8000: "HTTP Alternate",
            8443: "HTTPS Alternate",
            3000: "HTTP Development",
            5000: "HTTP Development",
            
            # SSH and Remote Access
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC",
            5901: "VNC",
            
            # Email Services
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            465: "SMTPS",
            587: "SMTP Submission",
            993: "IMAPS",
            995: "POP3S",
            
            # File Transfer
            21: "FTP",
            22: "SFTP",
            69: "TFTP",
            115: "SFTP",
            
            # Database Services
            1433: "SQL Server",
            1521: "Oracle",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            
            # Directory Services
            389: "LDAP",
            636: "LDAPS",
            88: "Kerberos",
            464: "Kerberos Change Password",
            
            # Network Services
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            123: "NTP",
            161: "SNMP",
            162: "SNMP Trap",
            514: "Syslog",
            
            # Application Services
            135: "RPC Endpoint Mapper",
            139: "NetBIOS Session",
            445: "SMB",
            902: "VMware ESX",
            1723: "PPTP",
            1812: "RADIUS",
            1813: "RADIUS Accounting",
            
            # Web Application Servers
            8009: "Apache Tomcat AJP",
            8080: "Apache Tomcat",
            8443: "Apache Tomcat SSL",
            9000: "SonarQube",
            9200: "Elasticsearch",
            9300: "Elasticsearch Transport",
            
            # Development and Testing
            3000: "Node.js/React Dev",
            4000: "Development Server",
            5000: "Flask/Python Dev",
            8000: "Django Dev",
            9000: "PHP-FPM",
            
            # Gaming and Entertainment
            25565: "Minecraft",
            27015: "Source Engine",
            7777: "Terraria",
            
            # Security and Monitoring
            10050: "Zabbix Agent",
            10051: "Zabbix Server",
            1984: "Big Brother",
            2049: "NFS",
            
            # Miscellaneous
            79: "Finger",
            113: "Ident",
            119: "NNTP",
            194: "IRC",
            443: "HTTPS",
            465: "SMTPS",
            631: "IPP",
            993: "IMAPS",
            995: "POP3S",
        }
    
    def load_udp_services(self):
        """Load UDP service definitions"""
        return {
            # Core Network Services
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            69: "TFTP",
            123: "NTP",
            161: "SNMP",
            162: "SNMP Trap",
            514: "Syslog",
            
            # Network Discovery
            137: "NetBIOS Name Service",
            138: "NetBIOS Datagram",
            5353: "mDNS",
            1900: "UPnP SSDP",
            
            # Authentication and Security
            88: "Kerberos",
            464: "Kerberos Change Password",
            500: "ISAKMP",
            4500: "IPSec NAT-T",
            1812: "RADIUS",
            1813: "RADIUS Accounting",
            
            # System Services
            520: "RIP",
            521: "RIPng",
            623: "IPMI",
            
            # Application Services
            1434: "SQL Server Browser",
            5432: "PostgreSQL",
            
            # Gaming
            27015: "Steam",
            
            # VoIP and Communication
            5060: "SIP",
            5061: "SIP TLS",
            
            # File Services
            2049: "NFS",
            111: "RPC Portmapper",
            
            # Printing
            631: "IPP",
            
            # Media and Streaming
            554: "RTSP",
            1935: "RTMP",
        }
    
    def identify_service(self, port, protocol='tcp'):
        """Identify service running on a specific port"""
        if protocol.lower() == 'tcp':
            service = self.tcp_services.get(port)
        elif protocol.lower() == 'udp':
            service = self.udp_services.get(port)
        else:
            service = None
        
        if service:
            return service
        else:
            return f"Unknown ({protocol.upper()}/{port})"
    
    def get_service_description(self, port, protocol='tcp'):
        """Get detailed service description"""
        service = self.identify_service(port, protocol)
        descriptions = {
            # Web Services
            "HTTP": "Hypertext Transfer Protocol - Web server",
            "HTTPS": "HTTP Secure - Encrypted web server",
            "HTTP Alternate": "Alternative HTTP port",
            
            # Remote Access
            "SSH": "Secure Shell - Remote login and file transfer",
            "Telnet": "Unencrypted remote login (insecure)",
            "RDP": "Remote Desktop Protocol",
            "VNC": "Virtual Network Computing - Remote desktop",
            
            # Email
            "SMTP": "Simple Mail Transfer Protocol - Email sending",
            "POP3": "Post Office Protocol - Email retrieval",
            "IMAP": "Internet Message Access Protocol - Email access",
            "SMTPS": "SMTP over SSL/TLS - Secure email sending",
            
            # File Transfer
            "FTP": "File Transfer Protocol - File transfer",
            "SFTP": "SSH File Transfer Protocol - Secure file transfer",
            "TFTP": "Trivial File Transfer Protocol - Simple file transfer",
            
            # Databases
            "SQL Server": "Microsoft SQL Server database",
            "MySQL": "MySQL database server",
            "PostgreSQL": "PostgreSQL database server",
            "Oracle": "Oracle database server",
            "Redis": "Redis key-value store",
            "MongoDB": "MongoDB document database",
            
            # Network Services
            "DNS": "Domain Name System - Name resolution",
            "DHCP": "Dynamic Host Configuration Protocol",
            "NTP": "Network Time Protocol - Time synchronization",
            "SNMP": "Simple Network Management Protocol",
            
            # Directory Services
            "LDAP": "Lightweight Directory Access Protocol",
            "LDAPS": "LDAP over SSL/TLS",
            "Kerberos": "Network authentication protocol",
            
            # File Sharing
            "SMB": "Server Message Block - Windows file sharing",
            "NetBIOS": "Network Basic Input/Output System",
            "NFS": "Network File System - Unix/Linux file sharing",
        }
        
        return descriptions.get(service, f"{service} - Port {port}/{protocol.upper()}")
    
    def get_common_ports(self, protocol='tcp', category=None):
        """Get list of common ports by category"""
        if protocol.lower() == 'tcp':
            services = self.tcp_services
        else:
            services = self.udp_services
        
        if not category:
            return list(services.keys())
        
        # Define port categories
        categories = {
            'web': [80, 443, 8080, 8000, 8443, 3000, 5000],
            'email': [25, 110, 143, 465, 587, 993, 995],
            'ftp': [21, 22, 69, 115],
            'database': [1433, 1521, 3306, 5432, 6379, 27017],
            'remote': [22, 23, 3389, 5900, 5901],
            'network': [53, 67, 68, 123, 161, 162, 514],
            'directory': [389, 636, 88, 464],
            'file_sharing': [139, 445, 2049, 111],
        }
        
        return categories.get(category.lower(), [])
    
    def is_dangerous_port(self, port, protocol='tcp'):
        """Check if port is commonly associated with security risks"""
        dangerous_ports = {
            'tcp': [
                23,    # Telnet - unencrypted
                135,   # RPC - often exploited
                139,   # NetBIOS - information disclosure
                445,   # SMB - frequent attack vector
                1433,  # SQL Server - database exposure
                1521,  # Oracle - database exposure
                3389,  # RDP - brute force attacks
                5900,  # VNC - often unencrypted
                6379,  # Redis - often misconfigured
            ],
            'udp': [
                69,    # TFTP - often misconfigured
                161,   # SNMP - information disclosure
                500,   # ISAKMP - VPN attacks
                1900,  # UPnP - exploitation vector
            ]
        }
        
        return port in dangerous_ports.get(protocol.lower(), [])
    
    def get_security_info(self, port, protocol='tcp'):
        """Get security information for a port"""
        service = self.identify_service(port, protocol)
        
        security_info = {
            'service': service,
            'risk_level': 'Low',
            'recommendations': [],
            'common_vulnerabilities': []
        }
        
        # High-risk services
        if self.is_dangerous_port(port, protocol):
            security_info['risk_level'] = 'High'
            
            if port == 23:
                security_info['recommendations'].append("Disable Telnet, use SSH instead")
                security_info['common_vulnerabilities'].append("Unencrypted authentication")
            
            elif port == 135:
                security_info['recommendations'].append("Restrict RPC access, use firewall")
                security_info['common_vulnerabilities'].append("Buffer overflow attacks")
            
            elif port in [139, 445]:
                security_info['recommendations'].append("Secure SMB configuration, disable if not needed")
                security_info['common_vulnerabilities'].append("Information disclosure, ransomware")
            
            elif port in [1433, 1521, 3306, 5432]:
                security_info['recommendations'].append("Secure database configuration, restrict access")
                security_info['common_vulnerabilities'].append("SQL injection, weak authentication")
            
            elif port == 3389:
                security_info['recommendations'].append("Use strong passwords, enable NLA")
                security_info['common_vulnerabilities'].append("Brute force attacks, RDP exploits")
        
        # Medium-risk services
        elif port in [21, 25, 53, 80, 110, 143]:
            security_info['risk_level'] = 'Medium'
            security_info['recommendations'].append("Keep service updated and properly configured")
        
        return security_info