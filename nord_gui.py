#!/usr/bin/env python3
"""
NORD GUI - Graphical Interface for NORD Security System
Developed by DevMonix Technologies (www.devmonix.io)
"""

ASCII_ART = """
╔══════════════════════════════════════════════════════════════╗
║  __        __   _                            _   _          ║
║  \ \      / /__| | ___ ___  _ __   ___  _ __| |_| |__       ║
║   \ \ /\ / / _ \ |/ __/ _ \| '_ \ / _ \| '__| __| '_ \      ║
║    \ V  V /  __/ | (_| (_) | |_) | (_) | |  | |_| | | |     ║
║     \_/\_/ \___|_|\___\___/| .__/ \___/|_|   \__|_| |_|     ║
║                           |_|                          ║
║   ╔══════════════════════════════════════════════════════╗  ║
║   ║  🛡️  NORD SECURITY SYSTEM FOR PARROT OS              ║  ║
║   ║  🦜  Real-time Monitoring & Threat Detection          ║  ║
║   ║  🔍  Vulnerability Scanning & Security Analytics      ║  ║
║   ╚══════════════════════════════════════════════════════╝  ║
╚══════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import time
from datetime import datetime
from pathlib import Path
import subprocess
from nord import NordSecurity

class NordGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NORD Security System - DevMonix Technologies")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1e1e1e')
        
        # Show splash screen
        self.show_splash()
        
        # Initialize NORD Security
        self.shield = NordSecurity()
        self.monitoring = False
        
        # Create GUI elements
        self.create_widgets()
        self.update_status()
        
        # Start auto-refresh
        self.auto_refresh()
        
    def show_splash(self):
        """Show ASCII art splash screen"""
        splash = tk.Toplevel(self.root)
        splash.title("NORD")
        splash.geometry("80x25")
        splash.configure(bg='#000000')
        splash.overrideredirect(True)
        
        # Center the splash screen
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() // 2) - (80 // 2)
        y = (splash.winfo_screenheight() // 2) - (25 // 2)
        splash.geometry(f"+{x}+{y}")
        
        # Display ASCII art
        text_widget = tk.Text(splash, bg='#000000', fg='#00ff00', 
                             font=('Courier', 8), relief=tk.FLAT, bd=0)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(1.0, ASCII_ART)
        text_widget.config(state=tk.DISABLED)
        
        # Auto-close splash after 3 seconds
        splash.after(3000, splash.destroy)
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = tk.Label(main_frame, text="🛡️ NORD Security Monitor", 
                              font=('Arial', 16, 'bold'), bg='#1e1e1e', fg='#00ff00')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Buttons
        self.start_btn = tk.Button(control_frame, text="▶ Start Monitoring", 
                                  command=self.toggle_monitoring, bg='#00aa00', fg='white',
                                  font=('Arial', 10, 'bold'), width=15)
        self.start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.scan_btn = tk.Button(control_frame, text="🔍 Scan Vulnerabilities", 
                                 command=self.run_scan, bg='#ffaa00', fg='black',
                                 font=('Arial', 10, 'bold'), width=15)
        self.scan_btn.grid(row=0, column=1, padx=5, pady=5)
        
        self.report_btn = tk.Button(control_frame, text="📊 Generate Report", 
                                   command=self.generate_report, bg='#0088ff', fg='white',
                                   font=('Arial', 10, 'bold'), width=15)
        self.report_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.config_btn = tk.Button(control_frame, text="⚙️ Configuration", 
                                   command=self.open_config, bg='#888888', fg='white',
                                   font=('Arial', 10, 'bold'), width=15)
        self.config_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # Status Panel
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Status indicators
        self.status_labels = {}
        status_items = [
            ("Monitoring", "status_monitoring"),
            ("Network", "status_network"),
            ("Processes", "status_processes"),
            ("Ports", "status_ports"),
            ("CPU Usage", "status_cpu"),
            ("Memory", "status_memory"),
            ("Disk", "status_disk")
        ]
        
        for i, (label, key) in enumerate(status_items):
            tk.Label(status_frame, text=f"{label}:", bg='#1e1e1e', fg='white',
                    font=('Arial', 10)).grid(row=i, column=0, sticky=tk.W, pady=2)
            self.status_labels[key] = tk.Label(status_frame, text="Unknown", 
                                              bg='#1e1e1e', fg='#ffff00',
                                              font=('Arial', 10, 'bold'))
            self.status_labels[key].grid(row=i, column=1, sticky=tk.W, pady=2, padx=(10, 0))
        
        # Events Panel
        events_frame = ttk.LabelFrame(main_frame, text="Security Events", padding="10")
        events_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Events listbox with scrollbar
        self.events_text = scrolledtext.ScrolledText(events_frame, height=20, width=60,
                                                     bg='#2a2a2a', fg='#00ff00',
                                                     font=('Courier', 9))
        self.events_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        events_frame.columnconfigure(0, weight=1)
        events_frame.rowconfigure(0, weight=1)
        
        # Statistics Panel
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=2, column=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=20, width=30,
                                                   bg='#2a2a2a', fg='#00ffff',
                                                   font=('Courier', 9))
        self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.rowconfigure(0, weight=1)
        
    def toggle_monitoring(self):
        if not self.monitoring:
            # Start monitoring in background
            self.monitoring = True
            self.start_btn.config(text="⏸ Stop Monitoring", bg='#ff0000')
            
            def monitor():
                self.shield.start_monitoring()
                
            threading.Thread(target=monitor, daemon=True).start()
        else:
            # Stop monitoring
            self.monitoring = False
            self.shield.stop_monitoring()
            self.start_btn.config(text="▶ Start Monitoring", bg='#00aa00')
            
    def run_scan(self):
        self.scan_btn.config(text="🔄 Scanning...", state='disabled')
        
        def scan():
            vulnerabilities = self.shield.scan_vulnerabilities()
            self.root.after(0, self.scan_complete, vulnerabilities)
            
        threading.Thread(target=scan, daemon=True).start()
        
    def scan_complete(self, vulnerabilities):
        self.scan_btn.config(text="🔍 Scan Vulnerabilities", state='normal')
        
        if vulnerabilities:
            message = f"Found {len(vulnerabilities)} potential issues:\n\n"
            for vuln in vulnerabilities[:3]:  # Show first 3
                message += f"• {vuln['type']} ({vuln['severity']})\n"
            if len(vulnerabilities) > 3:
                message += f"\n... and {len(vulnerabilities) - 3} more"
                
            messagebox.showwarning("Vulnerability Scan Results", message)
        else:
            messagebox.showinfo("Vulnerability Scan Results", "No vulnerabilities found!")
            
    def generate_report(self):
        self.report_btn.config(text="🔄 Generating...", state='disabled')
        
        def generate():
            report = self.shield.generate_report()
            self.root.after(0, self.report_complete, report)
            
        threading.Thread(target=generate, daemon=True).start()
        
    def report_complete(self, report):
        self.report_btn.config(text="📊 Generate Report", state='normal')
        
        if report:
            message = f"Report generated successfully!\n\n"
            message += f"Total Events: {report['total_events']}\n"
            message += f"Critical: {report['events_by_severity'].get('CRITICAL', 0)}\n"
            message += f"High: {report['events_by_severity'].get('HIGH', 0)}\n"
            message += f"Medium: {report['events_by_severity'].get('MEDIUM', 0)}\n"
            message += f"Low: {report['events_by_severity'].get('LOW', 0)}\n"
            
            messagebox.showinfo("Report Generated", message)
        else:
            messagebox.showerror("Error", "Failed to generate report!")
            
    def open_config(self):
        config_file = Path.home() / '.parrot_shield' / 'config.json'
        if config_file.exists():
            # Open with default text editor
            try:
                subprocess.run(['xdg-open', str(config_file)], check=False)
            except:
                messagebox.showerror("Error", f"Could not open config file: {config_file}")
        else:
            messagebox.showinfo("Configuration", f"Config file will be created at: {config_file}")
            
    def update_status(self):
        # Update monitoring status
        self.status_labels['status_monitoring'].config(
            text="Running" if self.monitoring else "Stopped",
            fg='#00ff00' if self.monitoring else '#ff0000'
        )
        
        # Update system stats
        try:
            import psutil
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_color = '#00ff00' if cpu_percent < 70 else '#ffff00' if cpu_percent < 90 else '#ff0000'
            self.status_labels['status_cpu'].config(text=f"{cpu_percent:.1f}%", fg=cpu_color)
            
            # Memory
            memory = psutil.virtual_memory()
            mem_color = '#00ff00' if memory.percent < 70 else '#ffff00' if memory.percent < 90 else '#ff0000'
            self.status_labels['status_memory'].config(text=f"{memory.percent:.1f}%", fg=mem_color)
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_color = '#00ff00' if disk.percent < 70 else '#ffff00' if disk.percent < 90 else '#ff0000'
            self.status_labels['status_disk'].config(text=f"{disk.percent:.1f}%", fg=disk_color)
            
            # Network connections
            connections = len(psutil.net_connections(kind='inet'))
            self.status_labels['status_network'].config(text=str(connections), fg='#00ff00')
            
            # Processes
            processes = len(list(psutil.process_iter()))
            self.status_labels['status_processes'].config(text=str(processes), fg='#00ff00')
            
            # Open ports
            open_ports = len([c for c in psutil.net_connections(kind='inet') if c.status == 'LISTEN'])
            self.status_labels['status_ports'].config(text=str(open_ports), fg='#00ff00')
            
        except Exception as e:
            for key in ['status_cpu', 'status_memory', 'status_disk', 'status_network', 'status_processes', 'status_ports']:
                self.status_labels[key].config(text="Error", fg='#ff0000')
                
        # Update events
        self.update_events()
        
        # Update statistics
        self.update_statistics()
        
    def update_events(self):
        events_file = Path.home() / '.parrot_shield' / 'logs' / 'security_events.json'
        
        try:
            if events_file.exists():
                with open(events_file, 'r') as f:
                    events = json.load(f)
                    
                # Clear and update events display
                self.events_text.delete(1.0, tk.END)
                
                for event in events[-20:]:  # Show last 20 events
                    timestamp = datetime.fromisoformat(event['timestamp']).strftime('%H:%M:%S')
                    severity = event['severity']
                    event_type = event['event_type']
                    description = event['description']
                    
                    # Color coding
                    if severity == 'CRITICAL':
                        color = '#ff0000'
                    elif severity == 'HIGH':
                        color = '#ff8800'
                    elif severity == 'MEDIUM':
                        color = '#ffff00'
                    else:
                        color = '#00ff00'
                        
                    self.events_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                    self.events_text.insert(tk.END, f"[{severity}] ", f'severity_{severity}')
                    self.events_text.insert(tk.END, f"{event_type}: ", 'event_type')
                    self.events_text.insert(tk.END, f"{description}\n", 'description')
                    
                # Configure tags
                self.events_text.tag_config('timestamp', foreground='#888888')
                self.events_text.tag_config('severity_CRITICAL', foreground='#ff0000')
                self.events_text.tag_config('severity_HIGH', foreground='#ff8800')
                self.events_text.tag_config('severity_MEDIUM', foreground='#ffff00')
                self.events_text.tag_config('severity_LOW', foreground='#00ff00')
                self.events_text.tag_config('event_type', foreground='#00ffff')
                self.events_text.tag_config('description', foreground='white')
                
        except Exception as e:
            self.events_text.delete(1.0, tk.END)
            self.events_text.insert(tk.END, f"Error loading events: {e}")
            
    def update_statistics(self):
        events_file = Path.home() / '.parrot_shield' / 'logs' / 'security_events.json'
        
        try:
            if events_file.exists():
                with open(events_file, 'r') as f:
                    events = json.load(f)
                    
                # Calculate statistics
                total_events = len(events)
                severity_counts = {}
                type_counts = {}
                
                for event in events:
                    severity = event['severity']
                    event_type = event['event_type']
                    
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    type_counts[event_type] = type_counts.get(event_type, 0) + 1
                    
                # Display statistics
                self.stats_text.delete(1.0, tk.END)
                self.stats_text.insert(tk.END, "=== EVENT STATISTICS ===\n\n", 'header')
                self.stats_text.insert(tk.END, f"Total Events: {total_events}\n\n", 'total')
                
                self.stats_text.insert(tk.END, "By Severity:\n", 'subtitle')
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = severity_counts.get(severity, 0)
                    self.stats_text.insert(tk.END, f"  {severity}: {count}\n", f'severity_{severity}')
                    
                self.stats_text.insert(tk.END, "\nBy Type:\n", 'subtitle')
                for event_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.stats_text.insert(tk.END, f"  {event_type}: {count}\n", 'type')
                    
                # Configure tags
                self.stats_text.tag_config('header', foreground='#00ffff', font=('Courier', 10, 'bold'))
                self.stats_text.tag_config('total', foreground='#00ff00', font=('Courier', 10, 'bold'))
                self.stats_text.tag_config('subtitle', foreground='#ffff00', font=('Courier', 9, 'bold'))
                self.stats_text.tag_config('severity_CRITICAL', foreground='#ff0000')
                self.stats_text.tag_config('severity_HIGH', foreground='#ff8800')
                self.stats_text.tag_config('severity_MEDIUM', foreground='#ffff00')
                self.stats_text.tag_config('severity_LOW', foreground='#00ff00')
                self.stats_text.tag_config('type', foreground='white')
                
        except Exception as e:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, f"Error loading statistics: {e}")
            
    def auto_refresh(self):
        # Auto-refresh every 5 seconds
        self.update_status()
        self.root.after(5000, self.auto_refresh)

if __name__ == '__main__':
    root = tk.Tk()
    app = NordGUI(root)
    root.mainloop()
