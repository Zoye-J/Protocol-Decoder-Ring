#!/usr/bin/env python
"""
Network Interface Detection - Clean Output
"""

import sys
import subprocess
import re

def main():
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=2)
        lines = result.stdout.split('\n')
        
        interfaces = []
        current = None
        
        for line in lines:
            if 'adapter' in line.lower():
                current = {'name': line.strip(), 'ips': []}
                interfaces.append(current)
            elif 'IPv4' in line and current:
                ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip:
                    current['ips'].append(ip.group(1))
        
        for i, iface in enumerate(interfaces):
            if iface['ips']:  # Only show interfaces with IPs
                ip_str = f"IPs: {iface['ips'][0]}" if len(iface['ips']) == 1 else f"IPs: {iface['ips']}"
                print(f"{i}: {iface['name']:40} | {ip_str}")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()