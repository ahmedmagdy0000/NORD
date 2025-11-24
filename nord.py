#!/usr/bin/env python3
"""
NORD Security System - Enterprise-grade Security Tool
Developed by DevMonix Technologies (www.devmonix.io)
A comprehensive security monitoring and threat detection system for Parrot OS
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

import os
import sys
import time
import json
import logging
import threading
import subprocess
import psutil
import socket
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import argparse

# Configuration
CONFIG_DIR = Path.home() / '.parrot_shield'
LOG_DIR = CONFIG_DIR / 'logs'
CONFIG_FILE = CONFIG_DIR / 'config.json'

@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: str
    event_type: str
    severity: str
    source: str
    description: str
    details: Dict

class NordSecurity:
    """Main NORD Security monitoring class"""
    
    def __init__(self):
        self.setup_directories()
        self.setup_logging()
        self.load_config()
        self.running = False
        self.monitoring_threads = []
        
    def setup_directories(self):
        """Create necessary directories"""
        CONFIG_DIR.mkdir(exist_ok=True)
        LOG_DIR.mkdir(exist_ok=True)
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = LOG_DIR / f'parrot_shield_{datetime.now().strftime("%Y%m%d")}.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            'monitoring': {
                'network_monitoring': True,
                'process_monitoring': True,
                'file_integrity': True,
                'port_monitoring': True,
                'log_monitoring': True
            },
            'thresholds': {
                'suspicious_connections': 10,
                'failed_logins': 5,
                'cpu_usage': 80,
                'memory_usage': 85,
                'disk_usage': 90
            },
            'alerts': {
                'email_enabled': False,
                'email_address': '',
                'desktop_notifications': True,
                'log_level': 'INFO'
            },
            'whitelist': {
                'trusted_ips': ['127.0.0.1', '::1'],
                'trusted_processes': ['systemd', 'gnome-shell', 'parrot'],
                'excluded_dirs': ['/proc', '/sys', '/dev']
            }
        }
        
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
                self.config = default_config
        else:
            self.config = default_config
            self.save_config()
            
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
            
    def log_event(self, event_type: str, severity: str, source: str, 
                  description: str, details: Dict = None):
        """Log a security event"""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            severity=severity,
            source=source,
            description=description,
            details=details or {}
        )
        
        # Log to file
        log_message = f"[{severity.upper()}] {event_type}: {description}"
        if severity.upper() == 'CRITICAL':
            self.logger.critical(log_message)
        elif severity.upper() == 'HIGH':
            self.logger.error(log_message)
        elif severity.upper() == 'MEDIUM':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
            
        # Save event to JSON file
        events_file = LOG_DIR / 'security_events.json'
        events = []
        if events_file.exists():
            try:
                with open(events_file, 'r') as f:
                    events = json.load(f)
            except:
                pass
                
        events.append(asdict(event))
        
        # Keep only last 1000 events
        if len(events) > 1000:
            events = events[-1000:]
            
        with open(events_file, 'w') as f:
            json.dump(events, f, indent=2)
            
        # Send desktop notification if enabled
        if self.config['alerts']['desktop_notifications'] and severity in ['HIGH', 'CRITICAL']:
            self.send_notification(f"ParrotShield Alert: {event_type}", description)
            
    def send_notification(self, title: str, message: str):
        """Send desktop notification"""
        try:
            subprocess.run(['notify-send', title, message], check=False)
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
            
    def monitor_network_connections(self):
        """Monitor network connections for suspicious activity"""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                suspicious_count = 0
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        if conn.raddr:
                            remote_ip = conn.raddr.ip
                            if remote_ip not in self.config['whitelist']['trusted_ips']:
                                suspicious_count += 1
                                
                if suspicious_count > self.config['thresholds']['suspicious_connections']:
                    self.log_event(
                        'NETWORK_SUSPICIOUS',
                        'HIGH',
                        'network_monitor',
                        f'High number of suspicious connections: {suspicious_count}',
                        {'count': suspicious_count}
                    )
                    
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(60)
                
    def monitor_processes(self):
        """Monitor system processes for suspicious activity"""
        while self.running:
            try:
                processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
                
                # Check for high CPU usage
                for proc in processes:
                    if proc.info['cpu_percent'] and proc.info['cpu_percent'] > self.config['thresholds']['cpu_usage']:
                        if proc.info['name'] not in self.config['whitelist']['trusted_processes']:
                            self.log_event(
                                'HIGH_CPU_USAGE',
                                'MEDIUM',
                                'process_monitor',
                                f"High CPU usage by process {proc.info['name']} ({proc.info['cpu_percent']}%)",
                                {'pid': proc.info['pid'], 'name': proc.info['name'], 'cpu_percent': proc.info['cpu_percent']}
                            )
                            
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                time.sleep(60)
                
    def monitor_open_ports(self):
        """Monitor open ports"""
        while self.running:
            try:
                open_ports = []
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN':
                        open_ports.append(conn.laddr.port)
                        
                # Check for unusual ports
                common_ports = {22, 80, 443, 21, 25, 53, 110, 143, 993, 995}
                unusual_ports = [port for port in open_ports if port not in common_ports]
                
                if unusual_ports:
                    self.log_event(
                        'UNUSUAL_PORTS',
                        'MEDIUM',
                        'port_monitor',
                        f'Unusual open ports detected: {unusual_ports}',
                        {'ports': unusual_ports}
                    )
                    
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Port monitoring error: {e}")
                time.sleep(300)
                
    def monitor_system_resources(self):
        """Monitor system resource usage"""
        while self.running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.config['thresholds']['cpu_usage']:
                    self.log_event(
                        'HIGH_SYSTEM_CPU',
                        'MEDIUM',
                        'system_monitor',
                        f'High system CPU usage: {cpu_percent}%',
                        {'cpu_percent': cpu_percent}
                    )
                    
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > self.config['thresholds']['memory_usage']:
                    self.log_event(
                        'HIGH_SYSTEM_MEMORY',
                        'MEDIUM',
                        'system_monitor',
                        f'High system memory usage: {memory.percent}%',
                        {'memory_percent': memory.percent}
                    )
                    
                # Disk usage
                disk = psutil.disk_usage('/')
                if disk.percent > self.config['thresholds']['disk_usage']:
                    self.log_event(
                        'HIGH_DISK_USAGE',
                        'HIGH',
                        'system_monitor',
                        f'High disk usage: {disk.percent}%',
                        {'disk_percent': disk.percent}
                    )
                    
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"System resource monitoring error: {e}")
                time.sleep(300)
                
    def monitor_login_attempts(self):
        """Monitor failed login attempts"""
        while self.running:
            try:
                # Check auth.log for failed logins
                auth_log = '/var/log/auth.log'
                if os.path.exists(auth_log):
                    result = subprocess.run(['grep', 'Failed password', auth_log], 
                                          capture_output=True, text=True)
                    failed_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                    
                    if failed_count > self.config['thresholds']['failed_logins']:
                        self.log_event(
                            'MULTIPLE_FAILED_LOGINS',
                            'HIGH',
                            'auth_monitor',
                            f'Multiple failed login attempts detected: {failed_count}',
                            {'failed_count': failed_count}
                        )
                        
                time.sleep(600)  # Check every 10 minutes
                
            except Exception as e:
                self.logger.error(f"Login monitoring error: {e}")
                time.sleep(600)
                
    def start_monitoring(self):
        """Start all monitoring threads"""
        self.running = True
        self.logger.info("Starting ParrotShield monitoring...")
        
        monitoring_functions = [
            (self.monitor_network_connections, 'Network Monitoring'),
            (self.monitor_processes, 'Process Monitoring'),
            (self.monitor_open_ports, 'Port Monitoring'),
            (self.monitor_system_resources, 'System Resource Monitoring'),
            (self.monitor_login_attempts, 'Login Monitoring')
        ]
        
        for func, name in monitoring_functions:
            if self.config['monitoring'].get(name.lower().replace(' ', '_'), True):
                thread = threading.Thread(target=func, daemon=True)
                thread.start()
                self.monitoring_threads.append(thread)
                self.logger.info(f"Started {name}")
                
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
        self.logger.info("Stopping ParrotShield monitoring...")
        
    def scan_vulnerabilities(self):
        """Perform basic vulnerability scan"""
        self.logger.info("Starting vulnerability scan...")
        
        vulnerabilities = []
        
        # Check for outdated packages (Debian/Parrot)
        try:
            result = subprocess.run(['apt', 'list', '--upgradable'], 
                                  capture_output=True, text=True)
            packages = result.stdout.strip().split('\n')[1:]  # Skip header
            if packages and packages[0]:
                vulnerabilities.append({
                    'type': 'outdated_packages',
                    'severity': 'MEDIUM',
                    'count': len([p for p in packages if p.strip()]),
                    'details': packages[:5]  # Show first 5
                })
        except Exception as e:
            self.logger.error(f"Package scan error: {e}")
            
        # Check for common security misconfigurations
        security_checks = [
            ('/etc/shadow permissions', 'stat -c "%a" /etc/shadow', '000'),
            ('/etc/passwd permissions', 'stat -c "%a" /etc/passwd', '644'),
            ('Firewall status', 'ufw status', 'active'),
        ]
        
        for check_name, command, expected in security_checks:
            try:
                result = subprocess.run(command.split(), capture_output=True, text=True)
                if expected not in result.stdout.lower():
                    vulnerabilities.append({
                        'type': 'security_misconfiguration',
                        'severity': 'HIGH',
                        'check': check_name,
                        'current': result.stdout.strip(),
                        'expected': expected
                    })
            except Exception as e:
                self.logger.error(f"Security check '{check_name}' error: {e}")
                
        # Log findings
        for vuln in vulnerabilities:
            self.log_event(
                'VULNERABILITY_FOUND',
                vuln['severity'],
                'vulnerability_scanner',
                f"Vulnerability detected: {vuln['type']}",
                vuln
            )
            
        self.logger.info(f"Vulnerability scan completed. Found {len(vulnerabilities)} issues.")
        return vulnerabilities
        
    def generate_report(self):
        """Generate security report"""
        events_file = LOG_DIR / 'security_events.json'
        if not events_file.exists():
            print("No security events found.")
            return
            
        try:
            with open(events_file, 'r') as f:
                events = json.load(f)
                
        except Exception as e:
            print(f"Error reading events: {e}")
            return
            
        # Generate summary
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events': len(events),
            'events_by_severity': {},
            'events_by_type': {},
            'recent_events': events[-10:]  # Last 10 events
        }
        
        for event in events:
            severity = event['severity']
            event_type = event['event_type']
            
            report['events_by_severity'][severity] = report['events_by_severity'].get(severity, 0) + 1
            report['events_by_type'][event_type] = report['events_by_type'].get(event_type, 0) + 1
            
        # Save report
        report_file = LOG_DIR / f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"Security report generated: {report_file}")
        return report
        
    def show_status(self):
        """Show current monitoring status"""
        print("\n=== NORD Security Status ===")
        print(f"Running: {self.running}")
        print(f"Active threads: {len([t for t in self.monitoring_threads if t.is_alive()])}")
        print(f"Log directory: {LOG_DIR}")
        print(f"Config file: {CONFIG_FILE}")
        
        # Show recent events
        events_file = LOG_DIR / 'security_events.json'
        if events_file.exists():
            try:
                with open(events_file, 'r') as f:
                    events = json.load(f)
                print(f"\nRecent events ({len(events)} total):")
                for event in events[-5:]:
                    print(f"  [{event['severity']}] {event['event_type']}: {event['description']}")
            except:
                pass
                
        print("\n=== Configuration ===")
        for category, settings in self.config.items():
            print(f"\n{category.upper()}:")
            for key, value in settings.items():
                print(f"  {key}: {value}")

def main():
    parser = argparse.ArgumentParser(
        description='NORD Security System - Enterprise-grade Security Tool\nDeveloped by DevMonix Technologies (www.devmonix.io)',)
    parser.add_argument('action', choices=['start', 'stop', 'status', 'scan', 'report', 'config'],
                       help='Action to perform')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Skip welcome banner')
    
    args = parser.parse_args()
    
    # Display ASCII art banner (unless disabled)
    if not args.no_banner and args.action not in ['status']:
        print(ASCII_ART)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔧 Version: 1.0.0 | 🐧 Platform: Parrot OS")
        print(f"🏢 Developed by DevMonix Technologies (www.devmonix.io)")
        print("─" * 62)
        time.sleep(1)  # Brief pause for dramatic effect
        
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    shield = NordSecurity()
    
    if args.action == 'start':
        print("🚀 Initializing NORD security monitoring systems...")
        shield.start_monitoring()
        print("✅ NORD monitoring started. Press Ctrl+C to stop.")
        print("📊 Real-time monitoring active - Events will be logged to ~/.parrot_shield/logs/")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            shield.stop_monitoring()
            print("\n🛑 NORD stopped gracefully.")
            
    elif args.action == 'stop':
        print("NORD is not running as a daemon. Use Ctrl+C to stop if running in foreground.")
        
    elif args.action == 'status':
        shield.show_status()
        
    elif args.action == 'scan':
        print("🔍 Initializing NORD vulnerability scanner...")
        vulnerabilities = shield.scan_vulnerabilities()
        print(f"\n📋 Scan completed. Found {len(vulnerabilities)} potential issues.")
        if vulnerabilities:
            print("⚠️  Review security events in ~/.parrot_shield/logs/ for details.")
        
    elif args.action == 'report':
        print("📊 Generating NORD security report...")
        report = shield.generate_report()
        
    elif args.action == 'config':
        print(f"⚙️  Configuration file: {CONFIG_FILE}")
        print("📝 Edit the file to customize NORD settings.")
        
if __name__ == '__main__':
    main()
