"""
Main GUI Window for Port Scanner Application
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import time
from datetime import datetime

from ..scanner.tcp_scanner import TCPScanner
from ..scanner.udp_scanner import UDPScanner
from ..scanner.ssl_scanner import SSLScanner
from ..utils.service_detector import ServiceDetector
from ..utils.export_utils import ExportUtils

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.setup_variables()
        self.setup_ui()
        self.setup_scanners()
        
    def setup_variables(self):
        """Initialize GUI variables"""
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.port_range_var = tk.StringVar(value="1-1000")
        self.timeout_var = tk.DoubleVar(value=1.0)
        self.threads_var = tk.IntVar(value=100)
        self.scan_type_var = tk.StringVar(value="TCP")
        self.ssl_check_var = tk.BooleanVar(value=True)
        
        self.scanning = False
        self.scan_results = []
        self.result_queue = queue.Queue()
        
    def setup_ui(self):
        """Create and setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        main_frame.rowconfigure(0, weight=1)
        
        # Setup tabs
        self.setup_scan_tab()
        self.setup_results_tab()
        self.setup_about_tab()
        
    def setup_scan_tab(self):
        """Setup the main scanning tab"""
        scan_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(scan_frame, text="Port Scanner")
        
        # Target configuration
        target_frame = ttk.LabelFrame(scan_frame, text="Target Configuration", padding="15")
        target_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        scan_frame.columnconfigure(0, weight=1)
        
        ttk.Label(target_frame, text="Target Host/IP:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        target_entry = ttk.Entry(target_frame, textvariable=self.target_var, font=('Arial', 10))
        target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=(0, 5))
        target_frame.columnconfigure(1, weight=1)
        
        ttk.Label(target_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        port_entry = ttk.Entry(target_frame, textvariable=self.port_range_var, font=('Arial', 10))
        port_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=(5, 0))
        
        # Scan options
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options", padding="15")
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Scan type selection
        ttk.Label(options_frame, text="Scan Type:").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        scan_type_frame = ttk.Frame(options_frame)
        scan_type_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=(0, 10))
        
        ttk.Radiobutton(scan_type_frame, text="TCP", variable=self.scan_type_var, value="TCP").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(scan_type_frame, text="UDP", variable=self.scan_type_var, value="UDP").grid(row=0, column=1, sticky=tk.W, padx=(20, 0))
        ttk.Radiobutton(scan_type_frame, text="Both", variable=self.scan_type_var, value="BOTH").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        
        # Advanced options
        ttk.Label(options_frame, text="Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        timeout_entry = ttk.Entry(options_frame, textvariable=self.timeout_var, width=10, font=('Arial', 10))
        timeout_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))
        
        ttk.Label(options_frame, text="Threads:").grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        threads_entry = ttk.Entry(options_frame, textvariable=self.threads_var, width=10, font=('Arial', 10))
        threads_entry.grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))
        
        ttk.Checkbutton(options_frame, text="SSL/TLS Detection", variable=self.ssl_check_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # Control buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(0, 15))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, style='Accent.TButton')
        self.scan_button.grid(row=0, column=0, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=2)
        
        # Progress and status
        progress_frame = ttk.LabelFrame(scan_frame, text="Scan Progress", padding="15")
        progress_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(progress_frame, textvariable=self.progress_var, font=('Arial', 10)).grid(row=0, column=0, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        progress_frame.columnconfigure(0, weight=1)
        
        # Quick results preview
        preview_frame = ttk.LabelFrame(scan_frame, text="Quick Results", padding="15")
        preview_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 0))
        scan_frame.rowconfigure(4, weight=1)
        
        # Create treeview for quick results
        columns = ('Port', 'Protocol', 'State', 'Service')
        self.preview_tree = ttk.Treeview(preview_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.preview_tree.heading(col, text=col)
            self.preview_tree.column(col, width=100)
        
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient='vertical', command=self.preview_tree.yview)
        self.preview_tree.configure(yscrollcommand=preview_scrollbar.set)
        
        self.preview_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        preview_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        
    def setup_results_tab(self):
        """Setup the detailed results tab"""
        results_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(results_frame, text="Detailed Results")
        
        # Results toolbar
        toolbar_frame = ttk.Frame(results_frame)
        toolbar_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        results_frame.columnconfigure(0, weight=1)
        
        ttk.Button(toolbar_frame, text="Export to CSV", command=self.export_csv).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(toolbar_frame, text="Export to JSON", command=self.export_json).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(toolbar_frame, text="Save Report", command=self.save_report).grid(row=0, column=2)
        
        # Detailed results text area
        text_frame = ttk.Frame(results_frame)
        text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.rowconfigure(1, weight=1)
        
        self.results_text = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10))
        results_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        # Configure text tags for formatting
        self.results_text.tag_configure("header", font=('Consolas', 12, 'bold'), foreground='blue')
        self.results_text.tag_configure("open", foreground='green', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure("closed", foreground='red')
        self.results_text.tag_configure("ssl", foreground='purple', font=('Consolas', 10, 'bold'))
        
    def setup_about_tab(self):
        """Setup the about/help tab"""
        about_frame = ttk.Frame(self.notebook, padding="30")
        self.notebook.add(about_frame, text="About")
        
        # About content
        about_text = """TCP/UDP Port Scanner v1.0

A comprehensive network port scanning tool with the following features:

• TCP and UDP port scanning
• SSL/TLS service detection
• Multi-threaded scanning for performance
• Service identification for common ports
• Export results to CSV, JSON, and reports
• Real-time progress tracking
• Professional GUI interface

Usage Instructions:
1. Enter target host/IP address
2. Specify port range (e.g., 1-1000, 80,443,22)
3. Select scan type (TCP, UDP, or Both)
4. Configure timeout and thread settings
5. Enable SSL detection if needed
6. Click 'Start Scan' to begin

Note: This tool is for educational and authorized testing purposes only.
Always ensure you have permission to scan the target systems."""
        
        about_label = ttk.Label(about_frame, text=about_text, font=('Arial', 10), justify=tk.LEFT)
        about_label.grid(row=0, column=0, sticky=(tk.W, tk.N))
        
    def setup_scanners(self):
        """Initialize scanner objects"""
        self.tcp_scanner = TCPScanner()
        self.udp_scanner = UDPScanner()
        self.ssl_scanner = SSLScanner()
        self.service_detector = ServiceDetector()
        self.export_utils = ExportUtils()
        
    def start_scan(self):
        """Start the port scanning process"""
        if self.scanning:
            return
            
        # Validate inputs
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target host/IP address")
            return
            
        port_range = self.port_range_var.get().strip()
        if not port_range:
            messagebox.showerror("Error", "Please enter a port range")
            return
            
        # Parse port range
        try:
            ports = self.parse_port_range(port_range)
            if not ports:
                raise ValueError("No valid ports specified")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid port range: {str(e)}")
            return
            
        # Update UI state
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_var.set("Initializing scan...")
        self.progress_bar.config(maximum=len(ports))
        self.progress_bar.config(value=0)
        
        # Clear previous results
        self.scan_results.clear()
        self.clear_preview_tree()
        
        # Start scanning in separate thread
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, ports),
            daemon=True
        )
        scan_thread.start()
        
        # Start result processing
        self.root.after(100, self.process_results)
        
    def run_scan(self, target, ports):
        """Run the actual scanning process"""
        try:
            scan_type = self.scan_type_var.get()
            timeout = self.timeout_var.get()
            max_threads = self.threads_var.get()
            check_ssl = self.ssl_check_var.get()
            
            total_ports = len(ports)
            scanned_ports = 0
            
            # TCP Scanning
            if scan_type in ['TCP', 'BOTH']:
                self.result_queue.put(('status', f"Scanning {len(ports)} TCP ports on {target}..."))
                
                tcp_results = self.tcp_scanner.scan_ports(
                    target, ports, timeout, max_threads,
                    progress_callback=lambda: self.result_queue.put(('progress', None))
                )
                
                for port, is_open in tcp_results:
                    if is_open:
                        service = self.service_detector.identify_service(port, 'tcp')
                        ssl_info = None
                        
                        if check_ssl and port in [443, 993, 995, 587, 465]:
                            ssl_info = self.ssl_scanner.check_ssl(target, port, timeout)
                        
                        result = {
                            'port': port,
                            'protocol': 'TCP',
                            'state': 'Open',
                            'service': service,
                            'ssl_info': ssl_info
                        }
                        
                        self.scan_results.append(result)
                        self.result_queue.put(('result', result))
                    
                    scanned_ports += 1
                    progress = (scanned_ports / total_ports) * 100
                    self.result_queue.put(('progress_update', progress))
            
            # UDP Scanning
            if scan_type in ['UDP', 'BOTH']:
                self.result_queue.put(('status', f"Scanning {len(ports)} UDP ports on {target}..."))
                
                udp_results = self.udp_scanner.scan_ports(
                    target, ports, timeout, max_threads,
                    progress_callback=lambda: self.result_queue.put(('progress', None))
                )
                
                for port, is_open in udp_results:
                    if is_open:
                        service = self.service_detector.identify_service(port, 'udp')
                        
                        result = {
                            'port': port,
                            'protocol': 'UDP',
                            'state': 'Open',
                            'service': service,
                            'ssl_info': None
                        }
                        
                        self.scan_results.append(result)
                        self.result_queue.put(('result', result))
            
            self.result_queue.put(('complete', len(self.scan_results)))
            
        except Exception as e:
            self.result_queue.put(('error', str(e)))
    
    def process_results(self):
        """Process scan results from the queue"""
        if not self.scanning:
            return
            
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == 'status':
                    self.progress_var.set(data)
                    
                elif msg_type == 'progress_update':
                    self.progress_bar.config(value=data)
                    
                elif msg_type == 'result':
                    self.add_result_to_preview(data)
                    
                elif msg_type == 'complete':
                    self.scan_complete(data)
                    return
                    
                elif msg_type == 'error':
                    self.scan_error(data)
                    return
                    
        except queue.Empty:
            pass
        
        if self.scanning:
            self.root.after(100, self.process_results)
    
    def add_result_to_preview(self, result):
        """Add scan result to preview tree"""
        port = result['port']
        protocol = result['protocol']
        state = result['state']
        service = result['service']
        
        item = self.preview_tree.insert('', 'end', values=(port, protocol, state, service))
        
        # Color code the result
        if state == 'Open':
            self.preview_tree.set(item, 'State', '✓ Open')
    
    def scan_complete(self, open_ports):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_var.set(f"Scan complete - Found {open_ports} open ports")
        self.progress_bar.config(value=self.progress_bar.cget('maximum'))
        
        self.generate_detailed_results()
        
    def scan_error(self, error):
        """Handle scan error"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_var.set("Scan failed")
        messagebox.showerror("Scan Error", f"Scan failed: {error}")
        
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_var.set("Scan stopped by user")
        
    def clear_results(self):
        """Clear all scan results"""
        self.scan_results.clear()
        self.clear_preview_tree()
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set("Results cleared")
        self.progress_bar.config(value=0)
        
    def clear_preview_tree(self):
        """Clear the preview tree"""
        for item in self.preview_tree.get_children():
            self.preview_tree.delete(item)
    
    def generate_detailed_results(self):
        """Generate detailed results in the results tab"""
        self.results_text.delete(1.0, tk.END)
        
        if not self.scan_results:
            self.results_text.insert(tk.END, "No open ports found.\n")
            return
        
        # Header
        header = f"Port Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"Target: {self.target_var.get()}\n"
        header += f"Scan Type: {self.scan_type_var.get()}\n"
        header += f"Open Ports Found: {len(self.scan_results)}\n"
        header += "=" * 60 + "\n\n"
        
        self.results_text.insert(tk.END, header, "header")
        
        # Group results by protocol
        tcp_results = [r for r in self.scan_results if r['protocol'] == 'TCP']
        udp_results = [r for r in self.scan_results if r['protocol'] == 'UDP']
        
        # TCP Results
        if tcp_results:
            self.results_text.insert(tk.END, "TCP Ports:\n", "header")
            for result in sorted(tcp_results, key=lambda x: x['port']):
                port_info = f"  Port {result['port']}: {result['service']}\n"
                self.results_text.insert(tk.END, port_info, "open")
                
                if result['ssl_info']:
                    ssl_text = f"    SSL/TLS: {result['ssl_info']}\n"
                    self.results_text.insert(tk.END, ssl_text, "ssl")
            
            self.results_text.insert(tk.END, "\n")
        
        # UDP Results
        if udp_results:
            self.results_text.insert(tk.END, "UDP Ports:\n", "header")
            for result in sorted(udp_results, key=lambda x: x['port']):
                port_info = f"  Port {result['port']}: {result['service']}\n"
                self.results_text.insert(tk.END, port_info, "open")
            
            self.results_text.insert(tk.END, "\n")
    
    def parse_port_range(self, port_range):
        """Parse port range string into list of ports"""
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                start, end = part.split('-', 1)
                start, end = int(start.strip()), int(end.strip())
                
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                    
                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}")
                ports.append(port)
        
        return list(set(ports))  # Remove duplicates
    
    def export_csv(self):
        """Export results to CSV"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                self.export_utils.export_to_csv(self.scan_results, filename)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def export_json(self):
        """Export results to JSON"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                self.export_utils.export_to_json(self.scan_results, filename)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def save_report(self):
        """Save detailed report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to save")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                report_data = {
                    'target': self.target_var.get(),
                    'scan_type': self.scan_type_var.get(),
                    'results': self.scan_results,
                    'timestamp': datetime.now().isoformat()
                }
                self.export_utils.save_report(report_data, filename)
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")