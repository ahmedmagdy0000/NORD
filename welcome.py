#!/usr/bin/env python3
"""
NORD Security System Welcome Screen
Developed by DevMonix Technologies (www.devmonix.io)
Beautiful ASCII art display for NORD Security System
"""

import time
import sys
from datetime import datetime

ASCII_ART = """
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║     ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗███╗   ██╗███████╗  ║
║     ████╗ ████║██╔════╝██╔═══██╗██║   ██║██║████╗  ██║██╔════╝  ║
║     ██╔████╔██║██║     ██║   ██║██║   ██║██║██╔██╗ ██║█████╗    ║
║     ██║╚██╔╝██║██║     ██║   ██║╚██╗ ██╔╝██║██║╚██╗██║██╔══╝    ║
║     ██║ ╚═╝ ██║╚██████╗╚██████╔╝ ╚████╔╝ ██║██║ ╚████║██║       ║
║     ╚═╝     ╚═╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚═╝╚═╝  ╚═══╝╚═╝       ║
║                                                                 ║
║     N   N   OOO   RRRR   DDDD                                   ║
║     NN  N  O   O  R   R  D   D                                  ║
║     N N N  O   O  RRRR   D   D                                  ║
║     N  NN  O   O  R  R   D   D                                  ║
║     N   N   OOO   R   R  DDDD                                   ║
║                                                                 ║
║   ╔═════════════════════════════════════════════════════════╗   ║
║   ║  🛡️  NORD SECURITY SYSTEM FOR PARROT OS                  ║   ║
║   ║  🦜  REAL-TIME MONITORING & THREAT DETECTION             ║   ║
║   ║  🔍  VULNERABILITY SCANNING & SECURITY ANALYTICS         ║   ║
║   ║  📊  COMPREHENSIVE LOGGING & REPORTING SYSTEM            ║   ║
║   ╚═════════════════════════════════════════════════════════╝   ║
╚═════════════════════════════════════════════════════════════════╝
"""

def typewriter_effect(text, delay=0.02):
    """Print text with typewriter effect and colors"""
    colors = {
        'NORD': '\033[1;32m',      # Green
        'SECURITY': '\033[1;34m',  # Blue  
        'SYSTEM': '\033[1;31m',    # Red
        'MONITORING': '\033[1;33m', # Yellow
        'DETECTION': '\033[1;35m',  # Magenta
        'VULNERABILITY': '\033[1;36m', # Cyan
        'ANALYTICS': '\033[1;37m',  # White
        'REPORTING': '\033[1;37m',  # White
        'reset': '\033[0m'
    }
    
    # Apply colors to keywords
    colored_text = text
    for keyword, color in colors.items():
        if keyword != 'reset':
            colored_text = colored_text.replace(keyword, f"{color}{keyword}{colors['reset']}")
    
    for char in colored_text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_welcome():
    """Display welcome screen with beautiful animations"""
    # Clear screen (works on most terminals)
    print('\033[2J\033[H', end='')
    
    # Animated initialization
    print("\033[1;36m🦜 Initializing NORD Security Systems...\033[0m", end='', flush=True)
    for i in range(3):
        time.sleep(0.5)
        print(".", end='', flush=True)
    print(" \033[1;32m✓\033[0m")
    time.sleep(0.5)
    
    # Display ASCII art with enhanced colors
    colored_art = ASCII_ART.replace('NORD', '\033[1;32mNORD\033[0m')  # Green
    colored_art = colored_art.replace('SECURITY', '\033[1;34mSECURITY\033[0m')  # Blue
    colored_art = colored_art.replace('SYSTEM', '\033[1;31mSYSTEM\033[0m')  # Red
    colored_art = colored_art.replace('MONITORING', '\033[1;33mMONITORING\033[0m')  # Yellow
    colored_art = colored_art.replace('DETECTION', '\033[1;35mDETECTION\033[0m')  # Magenta
    colored_art = colored_art.replace('VULNERABILITY', '\033[1;36mVULNERABILITY\033[0m')  # Cyan
    colored_art = colored_art.replace('ANALYTICS', '\033[1;37mANALYTICS\033[0m')  # White
    colored_art = colored_art.replace('REPORTING', '\033[1;37mREPORTING\033[0m')  # White
    
    print(colored_art)
    
    # Enhanced animated info lines with icons
    info_lines = [
        f"\033[1;36m🕐\033[0m Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"\033[1;33m🔧\033[0m Version: 1.0.0 | \033[1;32m🐧\033[0m Platform: Parrot OS",
        f"\033[1;31m🛡️\033[0m Status: \033[1;32mReady to protect your system\033[0m",
        f"\033[1;34m📡\033[0m Network: \033[1;32mMonitoring active connections\033[0m",
        f"\033[1;35m🔍\033[0m Scanner: \033[1;32mVulnerability detection enabled\033[0m"
    ]
    
    for line in info_lines:
        typewriter_effect(line, 0.01)
    
    print("\n" + "\033[1;36m" + "─" * 62 + "\033[0m")
    
    # Enhanced final messages
    typewriter_effect("✅ NORD is ready! Use '\033[1;32mnord start\033[0m' to begin monitoring.", 0.02)
    typewriter_effect("📖 Use '\033[1;32mnord --help\033[0m' for all available commands.", 0.02)
    
    print(f"\n\033[1;36m🦜 Stay secure, stay protected! \033[1;32m[NORD Security System]\033[0m")
    print(f"\033[1;34mDeveloped by DevMonix Technologies (www.devmonix.io)\033[0m")

if __name__ == '__main__':
    show_welcome()
