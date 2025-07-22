"""
Export Utilities Module
Handles exporting scan results to various formats
"""

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import os

class ExportUtils:
    def __init__(self):
        pass
    
    def export_to_csv(self, results, filename):
        """Export scan results to CSV format"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Port', 'Protocol', 'State', 'Service', 'SSL_Info', 'Timestamp']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Write results
                timestamp = datetime.now().isoformat()
                for result in results:
                    ssl_info = result.get('ssl_info', '')
                    if ssl_info and isinstance(ssl_info, dict):
                        ssl_info = str(ssl_info)
                    elif ssl_info is None:
                        ssl_info = ''
                    
                    writer.writerow({
                        'Port': result['port'],
                        'Protocol': result['protocol'],
                        'State': result['state'],
                        'Service': result['service'],
                        'SSL_Info': ssl_info,
                        'Timestamp': timestamp
                    })
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to export CSV: {str(e)}")
    
    def export_to_json(self, results, filename):
        """Export scan results to JSON format"""
        try:
            export_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_results': len(results),
                    'export_format': 'json'
                },
                'results': results
            }
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False, default=str)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to export JSON: {str(e)}")
    
    def export_to_xml(self, results, filename):
        """Export scan results to XML format"""
        try:
            root = ET.Element("PortScanResults")
            
            # Add scan info
            scan_info = ET.SubElement(root, "ScanInfo")
            ET.SubElement(scan_info, "Timestamp").text = datetime.now().isoformat()
            ET.SubElement(scan_info, "TotalResults").text = str(len(results))
            
            # Add results
            results_elem = ET.SubElement(root, "Results")
            
            for result in results:
                result_elem = ET.SubElement(results_elem, "Result")
                ET.SubElement(result_elem, "Port").text = str(result['port'])
                ET.SubElement(result_elem, "Protocol").text = result['protocol']
                ET.SubElement(result_elem, "State").text = result['state']
                ET.SubElement(result_elem, "Service").text = result['service']
                
                if result.get('ssl_info'):
                    ssl_elem = ET.SubElement(result_elem, "SSLInfo")
                    ssl_elem.text = str(result['ssl_info'])
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to export XML: {str(e)}")
    
    def save_report(self, scan_data, filename):
        """Save detailed scan report in text format"""
        try:
            with open(filename, 'w', encoding='utf-8') as report_file:
                # Report header
                report_file.write("TCP/UDP Port Scanner - Detailed Report\n")
                report_file.write("=" * 50 + "\n\n")
                
                # Scan information
                report_file.write(f"Scan Target: {scan_data.get('target', 'Unknown')}\n")
                report_file.write(f"Scan Type: {scan_data.get('scan_type', 'Unknown')}\n")
                report_file.write(f"Timestamp: {scan_data.get('timestamp', datetime.now().isoformat())}\n")
                report_file.write(f"Total Open Ports: {len(scan_data.get('results', []))}\n\n")
                
                results = scan_data.get('results', [])
                
                if not results:
                    report_file.write("No open ports were found during the scan.\n")
                    return True
                
                # Group results by protocol
                tcp_results = [r for r in results if r['protocol'] == 'TCP']
                udp_results = [r for r in results if r['protocol'] == 'UDP']
                
                # TCP Results Section
                if tcp_results:
                    report_file.write("TCP PORTS\n")
                    report_file.write("-" * 20 + "\n")
                    
                    for result in sorted(tcp_results, key=lambda x: x['port']):
                        report_file.write(f"\nPort {result['port']}/TCP\n")
                        report_file.write(f"  State: {result['state']}\n")
                        report_file.write(f"  Service: {result['service']}\n")
                        
                        if result.get('ssl_info'):
                            report_file.write(f"  SSL/TLS Info:\n")
                            ssl_lines = str(result['ssl_info']).split('\n')
                            for line in ssl_lines:
                                if line.strip():
                                    report_file.write(f"    {line.strip()}\n")
                    
                    report_file.write("\n")
                
                # UDP Results Section
                if udp_results:
                    report_file.write("UDP PORTS\n")
                    report_file.write("-" * 20 + "\n")
                    
                    for result in sorted(udp_results, key=lambda x: x['port']):
                        report_file.write(f"\nPort {result['port']}/UDP\n")
                        report_file.write(f"  State: {result['state']}\n")
                        report_file.write(f"  Service: {result['service']}\n")
                    
                    report_file.write("\n")
                
                # Summary section
                report_file.write("SCAN SUMMARY\n")
                report_file.write("-" * 20 + "\n")
                report_file.write(f"Total TCP ports found: {len(tcp_results)}\n")
                report_file.write(f"Total UDP ports found: {len(udp_results)}\n")
                report_file.write(f"Total open ports: {len(results)}\n\n")
                
                # Security considerations
                report_file.write("SECURITY CONSIDERATIONS\n")
                report_file.write("-" * 30 + "\n")
                
                high_risk_ports = []
                for result in results:
                    port = result['port']
                    protocol = result['protocol'].lower()
                    
                    # Identify potentially risky open ports
                    risky_tcp = [23, 135, 139, 445, 1433, 1521, 3389, 5900]
                    risky_udp = [69, 161, 500, 1900]
                    
                    if (protocol == 'tcp' and port in risky_tcp) or \
                       (protocol == 'udp' and port in risky_udp):
                        high_risk_ports.append(result)
                
                if high_risk_ports:
                    report_file.write("High-risk ports detected:\n")
                    for result in high_risk_ports:
                        report_file.write(f"  - Port {result['port']}/{result['protocol']}: {result['service']}\n")
                    report_file.write("\nRecommendation: Review these services for security hardening.\n\n")
                else:
                    report_file.write("No obviously high-risk ports detected.\n\n")
                
                # Footer
                report_file.write("Report generated by TCP/UDP Port Scanner v1.0\n")
                report_file.write(f"Report saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to save report: {str(e)}")
    
    def export_nmap_style(self, results, filename, target):
        """Export results in Nmap-style format"""
        try:
            with open(filename, 'w', encoding='utf-8') as nmap_file:
                # Nmap-style header
                nmap_file.write(f"# Port scan results for {target}\n")
                nmap_file.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                nmap_file.write(f"# TCP/UDP Port Scanner v1.0\n\n")
                
                nmap_file.write(f"Host: {target}\n")
                nmap_file.write("Status: Up\n\n")
                
                if not results:
                    nmap_file.write("All scanned ports are closed or filtered.\n")
                    return True
                
                # Group and sort results
                tcp_results = sorted([r for r in results if r['protocol'] == 'TCP'], 
                                   key=lambda x: x['port'])
                udp_results = sorted([r for r in results if r['protocol'] == 'UDP'], 
                                   key=lambda x: x['port'])
                
                # TCP ports
                if tcp_results:
                    nmap_file.write("PORT      STATE  SERVICE\n")
                    for result in tcp_results:
                        port_str = f"{result['port']}/tcp"
                        state = result['state'].lower()
                        service = result['service']
                        nmap_file.write(f"{port_str:<9} {state:<6} {service}\n")
                    nmap_file.write("\n")
                
                # UDP ports
                if udp_results:
                    nmap_file.write("PORT      STATE  SERVICE\n")
                    for result in udp_results:
                        port_str = f"{result['port']}/udp"
                        state = result['state'].lower()
                        service = result['service']
                        nmap_file.write(f"{port_str:<9} {state:<6} {service}\n")
                    nmap_file.write("\n")
                
                # Summary
                nmap_file.write(f"# Scan completed: {len(results)} open ports found\n")
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to export Nmap-style: {str(e)}")
    
    def get_export_formats(self):
        """Get list of available export formats"""
        return {
            'csv': {'extension': '.csv', 'description': 'Comma Separated Values'},
            'json': {'extension': '.json', 'description': 'JavaScript Object Notation'},
            'xml': {'extension': '.xml', 'description': 'Extensible Markup Language'},
            'txt': {'extension': '.txt', 'description': 'Plain Text Report'},
            'nmap': {'extension': '.txt', 'description': 'Nmap-style Output'}
        }
    
    def auto_export(self, results, base_filename, formats=['csv', 'json']):
        """Automatically export to multiple formats"""
        exported_files = []
        
        for fmt in formats:
            try:
                filename = f"{base_filename}.{fmt}"
                
                if fmt == 'csv':
                    self.export_to_csv(results, filename)
                elif fmt == 'json':
                    self.export_to_json(results, filename)
                elif fmt == 'xml':
                    self.export_to_xml(results, filename)
                
                exported_files.append(filename)
                
            except Exception as e:
                print(f"Failed to export {fmt}: {str(e)}")
        
        return exported_files