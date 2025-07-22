# TCP/UDP Port Scanner

A comprehensive network port scanning tool with both web interface and command-line capabilities.

## Features

### 🔍 Comprehensive Scanning
- **TCP Port Scanning**: Fast, multi-threaded TCP port detection
- **UDP Port Scanning**: Intelligent UDP service detection with protocol-specific probes
- **SSL/TLS Analysis**: Certificate inspection and security assessment
- **Service Identification**: Automatic identification of services running on open ports

### 🎯 Advanced Capabilities
- **Multi-threaded Scanning**: Configurable concurrent connections for optimal performance
- **Smart Port Detection**: Higher accuracy for common services and protocols
- **Security Assessment**: Risk level analysis for discovered services
- **Real-time Progress**: Live updates during scanning process

### 💻 User Interface
- **Modern Web Interface**: Clean, responsive design with real-time updates
- **Professional Layout**: Organized sections for configuration, results, and analysis
- **Export Functionality**: CSV export and detailed reporting
- **Mobile Responsive**: Works seamlessly on desktop and mobile devices

### 📊 Reporting & Analysis
- **Detailed Reports**: Comprehensive scan summaries with security insights
- **Statistics Dashboard**: Real-time scanning statistics and metrics
- **Risk Assessment**: Color-coded risk levels for discovered services
- **Export Options**: Multiple export formats for integration with other tools

## Quick Start

### Web Interface
1. Open `index.html` in your web browser
2. Enter target host/IP address
3. Configure port range and scan options
4. Click "Start Scan" to begin analysis
5. View results in real-time and export when complete

### Command Line Usage
```bash
# Basic scan
python scanner.py google.com

# Custom port range
python scanner.py 192.168.1.1 1 1000

# Scan specific ports
python scanner.py example.com 80 443
```

## Configuration Options

### Scan Types
- **TCP Scan**: Traditional TCP connect scanning
- **UDP Scan**: UDP service detection with intelligent probes
- **SSL/TLS Detection**: Certificate analysis for encrypted services

### Performance Settings
- **Timeout**: Connection timeout in milliseconds (100-10000ms)
- **Concurrent Scans**: Number of simultaneous connections (1-200)
- **Port Range**: Flexible port specification (individual ports or ranges)

### Quick Presets
- **Common Ports**: Standard service ports (1-1000)
- **All Ports**: Complete port range (1-65535)
- **Web Services**: HTTP/HTTPS and related ports
- **Database Ports**: Common database service ports

## Security Features

### Risk Assessment
- **Low Risk**: Standard services with good security practices
- **Medium Risk**: Services requiring careful configuration
- **High Risk**: Services with known security concerns
- **Unknown Risk**: Unidentified services requiring investigation

### SSL/TLS Analysis
- Certificate validation and expiration checking
- Cipher suite identification
- Protocol version detection
- Security vulnerability assessment

## Technical Details

### Scanning Techniques
- **TCP Connect Scanning**: Full three-way handshake for reliable detection
- **UDP Probing**: Service-specific probes for accurate UDP detection
- **SSL Handshake**: Complete SSL/TLS negotiation for certificate analysis
- **Service Fingerprinting**: Banner grabbing and response analysis

### Performance Optimization
- **Intelligent Threading**: Adaptive thread management for optimal performance
- **Connection Pooling**: Efficient resource utilization
- **Timeout Management**: Configurable timeouts for different network conditions
- **Progress Tracking**: Real-time scanning progress and statistics

## Use Cases

### Network Security Assessment
- Identify exposed services on network hosts
- Validate firewall configurations
- Discover unauthorized services
- Assess SSL/TLS security posture

### System Administration
- Verify service availability
- Troubleshoot network connectivity
- Document network infrastructure
- Monitor service changes over time

### Penetration Testing
- Reconnaissance and enumeration
- Service identification and fingerprinting
- SSL/TLS security assessment
- Network mapping and documentation

## Legal Notice

This tool is designed for authorized security testing and network administration purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems they do not own or have explicit permission to test.

## Requirements

- Modern web browser (Chrome, Firefox, Safari, Edge)
- Python 3.6+ (for command-line functionality)
- Network connectivity to target hosts

## Browser Compatibility

- ✅ Chrome 80+
- ✅ Firefox 75+
- ✅ Safari 13+
- ✅ Edge 80+
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)

## Contributing

This project welcomes contributions for:
- Additional service detection signatures
- Performance optimizations
- User interface improvements
- Documentation enhancements
- Security feature additions

---

**Professional Network Security Tool** | **For Authorized Testing Only**