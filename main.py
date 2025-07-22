#!/usr/bin/env python3
"""
TCP/UDP Port Scanner - Main Application
A comprehensive network port scanning tool with GUI interface
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.gui.main_window import PortScannerGUI

def main():
    """Main application entry point"""
    try:
        # Create and configure the main window
        root = tk.Tk()
        root.title("TCP/UDP Port Scanner")
        root.geometry("1000x700")
        root.minsize(800, 600)
        
        # Set application icon (using default for now)
        try:
            # You can add a custom icon here if needed
            pass
        except:
            pass
        
        # Initialize the main application
        app = PortScannerGUI(root)
        
        # Center the window on screen
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 2
        root.geometry(f"+{x}+{y}")
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start application: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()