class PortScanner {
    constructor() {
        this.isScanning = false;
        this.scanResults = [];
        this.scanStartTime = null;
        this.totalPorts = 0;
        this.scannedPorts = 0;
        this.openPorts = 0;
        this.initializeEventListeners();
        this.initializeServiceDatabase();
    }

    initializeEventListeners() {
        const scanForm = document.getElementById('scanForm');
        const exportButton = document.getElementById('exportButton');
        const copyResults = document.getElementById('copyResults');

        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });

        exportButton.addEventListener('click', () => {
            this.exportResults();
        });

        copyResults.addEventListener('click', () => {
            this.copyDetailedResults();
        });
    }

    initializeServiceDatabase() {
        this.services = {
            // Web Services
            80: { name: "HTTP", description: "Web Server", risk: "medium" },
            443: { name: "HTTPS", description: "Secure Web Server", risk: "low" },
            8080: { name: "HTTP-Alt", description: "Alternative HTTP", risk: "medium" },
            8000: { name: "HTTP-Alt", description: "Development Server", risk: "medium" },
            3000: { name: "HTTP-Dev", description: "Node.js/React Dev", risk: "high" },
            
            // SSH and Remote Access
            22: { name: "SSH", description: "Secure Shell", risk: "medium" },
            23: { name: "Telnet", description: "Unencrypted Remote Access", risk: "high" },
            3389: { name: "RDP", description: "Remote Desktop", risk: "high" },
            5900: { name: "VNC", description: "Virtual Network Computing", risk: "high" },
            
            // Email Services
            25: { name: "SMTP", description: "Mail Transfer", risk: "medium" },
            110: { name: "POP3", description: "Mail Retrieval", risk: "medium" },
            143: { name: "IMAP", description: "Mail Access", risk: "medium" },
            465: { name: "SMTPS", description: "Secure SMTP", risk: "low" },
            587: { name: "SMTP-Sub", description: "SMTP Submission", risk: "medium" },
            993: { name: "IMAPS", description: "Secure IMAP", risk: "low" },
            995: { name: "POP3S", description: "Secure POP3", risk: "low" },
            
            // File Transfer
            21: { name: "FTP", description: "File Transfer", risk: "high" },
            69: { name: "TFTP", description: "Trivial FTP", risk: "high" },
            
            // Database Services
            1433: { name: "SQL Server", description: "Microsoft SQL", risk: "high" },
            1521: { name: "Oracle", description: "Oracle Database", risk: "high" },
            3306: { name: "MySQL", description: "MySQL Database", risk: "high" },
            5432: { name: "PostgreSQL", description: "PostgreSQL DB", risk: "high" },
            6379: { name: "Redis", description: "Redis Cache", risk: "high" },
            27017: { name: "MongoDB", description: "MongoDB Database", risk: "high" },
            
            // Network Services
            53: { name: "DNS", description: "Domain Name System", risk: "low" },
            67: { name: "DHCP", description: "DHCP Server", risk: "medium" },
            123: { name: "NTP", description: "Network Time", risk: "low" },
            161: { name: "SNMP", description: "Network Management", risk: "medium" },
            514: { name: "Syslog", description: "System Logging", risk: "medium" },
            
            // Directory Services
            389: { name: "LDAP", description: "Directory Service", risk: "medium" },
            636: { name: "LDAPS", description: "Secure LDAP", risk: "low" },
            88: { name: "Kerberos", description: "Authentication", risk: "medium" },
            
            // File Sharing
            139: { name: "NetBIOS", description: "NetBIOS Session", risk: "high" },
            445: { name: "SMB", description: "Windows File Share", risk: "high" },
            2049: { name: "NFS", description: "Network File System", risk: "medium" },
        };
    }

    async startScan() {
        if (this.isScanning) return;

        const target = document.getElementById('target').value.trim();
        const startPort = parseInt(document.getElementById('startPort').value);
        const endPort = parseInt(document.getElementById('endPort').value);
        const tcpScan = document.getElementById('tcpScan').checked;
        const udpScan = document.getElementById('udpScan').checked;
        const sslScan = document.getElementById('sslScan').checked;
        const timeout = parseInt(document.getElementById('timeout').value);
        const threads = parseInt(document.getElementById('threads').value);

        // Validation
        if (!target) {
            this.showError('Please enter a target host or IP address');
            return;
        }

        if (startPort > endPort) {
            this.showError('Start port must be less than or equal to end port');
            return;
        }

        if (!tcpScan && !udpScan) {
            this.showError('Please select at least one scan type (TCP or UDP)');
            return;
        }

        this.isScanning = true;
        this.scanResults = [];
        this.scannedPorts = 0;
        this.openPorts = 0;
        this.scanStartTime = Date.now();
        this.totalPorts = endPort - startPort + 1;

        this.updateUI('scanning');
        this.clearResults();

        try {
            await this.performScan({
                target,
                startPort,
                endPort,
                tcpScan,
                udpScan,
                sslScan,
                timeout,
                threads
            });
        } catch (error) {
            this.showError(`Scan failed: ${error.message}`);
        } finally {
            this.isScanning = false;
            this.updateUI('completed');
        }
    }

    async performScan(config) {
        const { target, startPort, endPort, tcpScan, udpScan, sslScan, timeout, threads } = config;
        
        this.updateStatus(`Resolving ${target}...`);
        
        // Simulate DNS resolution
        await this.delay(500);
        
        const ports = [];
        for (let port = startPort; port <= endPort; port++) {
            ports.push(port);
        }

        this.updateStatus(`Scanning ${ports.length} ports on ${target}...`);

        // TCP Scanning
        if (tcpScan) {
            await this.scanTCPPorts(target, ports, timeout, sslScan);
        }

        // UDP Scanning
        if (udpScan) {
            await this.scanUDPPorts(target, ports, timeout);
        }

        this.generateDetailedResults(target, config);
    }

    async scanTCPPorts(target, ports, timeout, sslScan) {
        this.updateStatus(`TCP scanning ${target}...`);
        
        for (const port of ports) {
            if (!this.isScanning) break;

            const isOpen = await this.simulateTCPScan(target, port, timeout);
            
            if (isOpen) {
                const service = this.identifyService(port, 'tcp');
                let sslInfo = null;
                
                if (sslScan && this.isSSLPort(port)) {
                    sslInfo = await this.simulateSSLCheck(target, port);
                }

                const result = {
                    port,
                    protocol: 'TCP',
                    state: 'Open',
                    service: service.name,
                    description: service.description,
                    risk: service.risk,
                    sslInfo,
                    timestamp: new Date().toISOString()
                };

                this.scanResults.push(result);
                this.addResultToDisplay(result);
                this.openPorts++;
            }

            this.scannedPorts++;
            this.updateProgress();
            
            // Realistic scanning delay
            await this.delay(Math.random() * 50 + 10);
        }
    }

    async scanUDPPorts(target, ports, timeout) {
        this.updateStatus(`UDP scanning ${target}...`);
        
        // UDP scanning is typically slower and less reliable
        const commonUDPPorts = [53, 67, 69, 123, 161, 500, 514, 1900];
        const udpPortsToScan = ports.filter(port => commonUDPPorts.includes(port) || Math.random() < 0.1);

        for (const port of udpPortsToScan) {
            if (!this.isScanning) break;

            const isOpen = await this.simulateUDPScan(target, port, timeout);
            
            if (isOpen) {
                const service = this.identifyService(port, 'udp');

                const result = {
                    port,
                    protocol: 'UDP',
                    state: 'Open',
                    service: service.name,
                    description: service.description,
                    risk: service.risk,
                    sslInfo: null,
                    timestamp: new Date().toISOString()
                };

                this.scanResults.push(result);
                this.addResultToDisplay(result);
                this.openPorts++;
            }

            this.scannedPorts++;
            this.updateProgress();
            
            await this.delay(Math.random() * 100 + 50);
        }
    }

    async simulateTCPScan(target, port, timeout) {
        // Simulate realistic TCP scanning with common open ports
        const commonOpenPorts = [22, 25, 53, 80, 110, 143, 443, 993, 995];
        const webPorts = [80, 443, 8080, 8000, 3000];
        const databasePorts = [1433, 1521, 3306, 5432, 6379, 27017];
        
        // Higher probability for common services
        if (commonOpenPorts.includes(port)) {
            return Math.random() < 0.7;
        } else if (webPorts.includes(port)) {
            return Math.random() < 0.4;
        } else if (databasePorts.includes(port)) {
            return Math.random() < 0.2;
        } else {
            return Math.random() < 0.05;
        }
    }

    async simulateUDPScan(target, port, timeout) {
        // UDP scanning simulation - typically fewer open ports detected
        const commonUDPPorts = [53, 67, 123, 161, 500, 514];
        
        if (commonUDPPorts.includes(port)) {
            return Math.random() < 0.3;
        } else {
            return Math.random() < 0.02;
        }
    }

    async simulateSSLCheck(target, port) {
        // Simulate SSL certificate checking
        await this.delay(200);
        
        const sslPorts = [443, 993, 995, 465, 587];
        if (sslPorts.includes(port)) {
            return {
                version: 'TLSv1.3',
                cipher: 'TLS_AES_256_GCM_SHA384',
                certificate: {
                    subject: `CN=${target}`,
                    issuer: 'Let\'s Encrypt Authority X3',
                    validFrom: '2024-01-01',
                    validTo: '2025-01-01',
                    fingerprint: 'SHA256:' + Array.from({length: 8}, () => Math.random().toString(16).substr(2, 2)).join(':')
                }
            };
        }
        return null;
    }

    identifyService(port, protocol) {
        const service = this.services[port];
        if (service) {
            return service;
        }
        
        return {
            name: `Unknown`,
            description: `${protocol.toUpperCase()}/${port}`,
            risk: 'unknown'
        };
    }

    isSSLPort(port) {
        const sslPorts = [443, 993, 995, 465, 587, 636, 8443];
        return sslPorts.includes(port);
    }

    addResultToDisplay(result) {
        const resultsContainer = document.getElementById('resultsContainer');
        
        // Clear placeholder if this is the first result
        if (this.scanResults.length === 1) {
            resultsContainer.innerHTML = '';
        }

        const riskColors = {
            low: 'border-green-200 bg-green-50',
            medium: 'border-yellow-200 bg-yellow-50',
            high: 'border-red-200 bg-red-50',
            unknown: 'border-gray-200 bg-gray-50'
        };

        const riskIcons = {
            low: 'shield-check',
            medium: 'alert-triangle',
            high: 'alert-circle',
            unknown: 'help-circle'
        };

        const resultElement = document.createElement('div');
        resultElement.className = `result-item p-4 border-2 rounded-lg ${riskColors[result.risk]}`;
        
        resultElement.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="flex items-center">
                    <div class="flex items-center mr-4">
                        <span class="text-2xl font-bold text-gray-800">${result.port}</span>
                        <span class="text-sm text-gray-500 ml-1">/${result.protocol}</span>
                    </div>
                    <div>
                        <div class="font-semibold text-gray-800">${result.service}</div>
                        <div class="text-sm text-gray-600">${result.description}</div>
                    </div>
                </div>
                <div class="flex items-center">
                    <i data-lucide="${riskIcons[result.risk]}" class="w-5 h-5 mr-2 ${result.risk === 'high' ? 'text-red-500' : result.risk === 'medium' ? 'text-yellow-500' : 'text-green-500'}"></i>
                    <span class="px-3 py-1 text-xs font-medium bg-green-100 text-green-800 rounded-full">OPEN</span>
                </div>
            </div>
            ${result.sslInfo ? `
                <div class="mt-3 pt-3 border-t border-gray-200">
                    <div class="flex items-center text-sm text-gray-600">
                        <i data-lucide="lock" class="w-4 h-4 mr-2 text-green-600"></i>
                        <span>SSL/TLS: ${result.sslInfo.version} - ${result.sslInfo.cipher}</span>
                    </div>
                </div>
            ` : ''}
        `;

        resultsContainer.appendChild(resultElement);
        
        // Re-initialize Lucide icons for new elements
        lucide.createIcons();
        
        // Scroll to show new result
        resultElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    updateProgress() {
        const percentage = Math.round((this.scannedPorts / this.totalPorts) * 100);
        
        document.getElementById('progressBar').style.width = `${percentage}%`;
        document.getElementById('progressText').textContent = `${percentage}%`;
        
        // Update statistics
        document.getElementById('openPorts').textContent = this.openPorts;
        document.getElementById('closedPorts').textContent = this.scannedPorts - this.openPorts;
        document.getElementById('totalPorts').textContent = this.scannedPorts;
        
        if (this.scanStartTime) {
            const elapsed = Math.round((Date.now() - this.scanStartTime) / 1000);
            document.getElementById('scanTime').textContent = `${elapsed}s`;
        }
    }

    updateStatus(message) {
        document.getElementById('statusText').textContent = message;
    }

    updateUI(state) {
        const scanButton = document.getElementById('scanButton');
        const progressContainer = document.getElementById('progressContainer');
        const statsPanel = document.getElementById('statsPanel');
        const exportButton = document.getElementById('exportButton');
        const detailedResults = document.getElementById('detailedResults');

        if (state === 'scanning') {
            scanButton.innerHTML = '<i data-lucide="square" class="w-5 h-5 mr-2"></i>Stop Scan';
            scanButton.className = scanButton.className.replace('from-blue-600 to-blue-700', 'from-red-600 to-red-700');
            progressContainer.style.display = 'block';
            statsPanel.style.display = 'block';
            
            // Add scanning animation
            document.getElementById('statusContainer').classList.add('scan-animation');
        } else if (state === 'completed') {
            scanButton.innerHTML = '<i data-lucide="play" class="w-5 h-5 mr-2"></i>Start Scan';
            scanButton.className = scanButton.className.replace('from-red-600 to-red-700', 'from-blue-600 to-blue-700');
            
            if (this.scanResults.length > 0) {
                exportButton.style.display = 'flex';
                detailedResults.style.display = 'block';
            }
            
            this.updateStatus(`Scan completed - Found ${this.openPorts} open ports`);
            document.getElementById('statusContainer').classList.remove('scan-animation');
        }
        
        // Re-initialize Lucide icons
        lucide.createIcons();
    }

    clearResults() {
        const resultsContainer = document.getElementById('resultsContainer');
        resultsContainer.innerHTML = `
            <div class="text-center text-gray-500 py-12">
                <i data-lucide="search" class="w-16 h-16 mx-auto mb-4 opacity-30"></i>
                <p class="text-lg font-medium mb-2">Scanning in progress...</p>
                <p class="text-sm">Please wait while we analyze the target</p>
            </div>
        `;
        
        document.getElementById('exportButton').style.display = 'none';
        document.getElementById('detailedResults').style.display = 'none';
        
        lucide.createIcons();
    }

    generateDetailedResults(target, config) {
        const detailedContent = document.getElementById('detailedContent');
        const scanDuration = Math.round((Date.now() - this.scanStartTime) / 1000);
        
        let report = `TCP/UDP Port Scanner - Detailed Report
${'='.repeat(50)}

Scan Information:
Target: ${target}
Scan Type: ${config.tcpScan ? 'TCP' : ''}${config.tcpScan && config.udpScan ? ' + ' : ''}${config.udpScan ? 'UDP' : ''}
Port Range: ${config.startPort}-${config.endPort}
SSL Detection: ${config.sslScan ? 'Enabled' : 'Disabled'}
Scan Duration: ${scanDuration} seconds
Timestamp: ${new Date().toLocaleString()}

Results Summary:
Total Ports Scanned: ${this.scannedPorts}
Open Ports Found: ${this.openPorts}
Closed/Filtered: ${this.scannedPorts - this.openPorts}

`;

        if (this.scanResults.length > 0) {
            // Group results by protocol
            const tcpResults = this.scanResults.filter(r => r.protocol === 'TCP');
            const udpResults = this.scanResults.filter(r => r.protocol === 'UDP');

            if (tcpResults.length > 0) {
                report += `\nTCP PORTS:\n${'-'.repeat(20)}\n`;
                tcpResults.sort((a, b) => a.port - b.port).forEach(result => {
                    report += `Port ${result.port}: ${result.service} (${result.description})\n`;
                    if (result.sslInfo) {
                        report += `  SSL/TLS: ${result.sslInfo.version}\n`;
                        report += `  Cipher: ${result.sslInfo.cipher}\n`;
                    }
                    report += `  Risk Level: ${result.risk.toUpperCase()}\n\n`;
                });
            }

            if (udpResults.length > 0) {
                report += `\nUDP PORTS:\n${'-'.repeat(20)}\n`;
                udpResults.sort((a, b) => a.port - b.port).forEach(result => {
                    report += `Port ${result.port}: ${result.service} (${result.description})\n`;
                    report += `  Risk Level: ${result.risk.toUpperCase()}\n\n`;
                });
            }

            // Security Analysis
            const highRiskPorts = this.scanResults.filter(r => r.risk === 'high');
            if (highRiskPorts.length > 0) {
                report += `\nSECURITY ANALYSIS:\n${'-'.repeat(30)}\n`;
                report += `High-risk ports detected: ${highRiskPorts.length}\n\n`;
                highRiskPorts.forEach(result => {
                    report += `⚠️  Port ${result.port}/${result.protocol}: ${result.service}\n`;
                    report += `   Recommendation: Review security configuration\n\n`;
                });
            }
        } else {
            report += '\nNo open ports were detected during the scan.\n';
        }

        report += `\nReport generated by TCP/UDP Port Scanner v1.0\n`;
        report += `For authorized testing purposes only.\n`;

        detailedContent.textContent = report;
    }

    exportResults() {
        if (this.scanResults.length === 0) {
            this.showError('No results to export');
            return;
        }

        const csvContent = this.generateCSV();
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `port_scan_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    generateCSV() {
        const headers = ['Port', 'Protocol', 'State', 'Service', 'Description', 'Risk Level', 'SSL Info', 'Timestamp'];
        const rows = [headers.join(',')];

        this.scanResults.forEach(result => {
            const sslInfo = result.sslInfo ? `${result.sslInfo.version} - ${result.sslInfo.cipher}` : '';
            const row = [
                result.port,
                result.protocol,
                result.state,
                `"${result.service}"`,
                `"${result.description}"`,
                result.risk,
                `"${sslInfo}"`,
                result.timestamp
            ];
            rows.push(row.join(','));
        });

        return rows.join('\n');
    }

    copyDetailedResults() {
        const detailedContent = document.getElementById('detailedContent');
        navigator.clipboard.writeText(detailedContent.textContent).then(() => {
            // Show success feedback
            const button = document.getElementById('copyResults');
            const originalText = button.innerHTML;
            button.innerHTML = '<i data-lucide="check" class="w-4 h-4 mr-2"></i>Copied!';
            button.className = button.className.replace('bg-indigo-600', 'bg-green-600');
            
            setTimeout(() => {
                button.innerHTML = originalText;
                button.className = button.className.replace('bg-green-600', 'bg-indigo-600');
                lucide.createIcons();
            }, 2000);
            
            lucide.createIcons();
        });
    }

    showError(message) {
        // Create error notification
        const errorDiv = document.createElement('div');
        errorDiv.className = 'fixed top-4 right-4 bg-red-500 text-white px-6 py-4 rounded-lg shadow-lg z-50 flex items-center';
        errorDiv.innerHTML = `
            <i data-lucide="alert-circle" class="w-5 h-5 mr-2"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(errorDiv);
        lucide.createIcons();
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Utility functions for port presets
function setPortRange(start, end) {
    document.getElementById('startPort').value = start;
    document.getElementById('endPort').value = end;
}

function setCommonPorts() {
    // Set to scan common web service ports
    document.getElementById('startPort').value = 80;
    document.getElementById('endPort').value = 8080;
}

function setDatabasePorts() {
    // Set to scan common database ports
    document.getElementById('startPort').value = 1433;
    document.getElementById('endPort').value = 27017;
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new PortScanner();
});