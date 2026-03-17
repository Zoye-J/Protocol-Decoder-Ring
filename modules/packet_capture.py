"""
Module 2: Packet Capture Engine
Captures and manages network traffic from sandboxed applications
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict, List, Optional, Tuple, Union

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'

# Try to import scapy - this is our primary packet capture library
try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, 
        Raw, DNS, DNSQR, ARP, conf
    )
    from scapy.utils import PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not installed. Run: pip install scapy")

# Try to import pyshark for advanced PCAP parsing - with better error handling
PYSHARK_AVAILABLE = False
try:
    # Use a timeout mechanism to prevent hanging imports
    import threading
    import time
    
    pyshark_imported = [False]
    import_error = [None]
    
    def import_pyshark():
        try:
            global pyshark
            import pyshark
            pyshark_imported[0] = True
        except Exception as e:
            import_error[0] = e
    
    # Run import in a thread with timeout
    import_thread = threading.Thread(target=import_pyshark)
    import_thread.daemon = True
    import_thread.start()
    import_thread.join(timeout=3)  # Wait max 3 seconds
    
    if import_thread.is_alive():
        print("⚠️  PyShark import timed out (may have compatibility issues)")
        PYSHARK_AVAILABLE = False
    elif pyshark_imported[0]:
        PYSHARK_AVAILABLE = True
        print("✅ PyShark loaded successfully")
    else:
        PYSHARK_AVAILABLE = False
        if import_error[0]:
            print(f"⚠️  PyShark import error: {import_error[0]}")
        else:
            print("⚠️  PyShark not installed. Run: pip install pyshark")
            
except Exception as e:
    PYSHARK_AVAILABLE = False
    print(f"⚠️  PyShark not available: {e}")

# Optional imports for better performance
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class PacketCapture:
    """
    Captures and manages network packets from the sandbox environment
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the packet capture engine
        """
        self.capture_id = self._generate_capture_id()
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Capture state
        self.packets = []
        self.captured_bytes = 0
        self.is_capturing = False
        self.capture_thread = None
        self.stop_capture = threading.Event()
        
        # Statistics
        self.stats = {
            "start_time": None,
            "end_time": None,
            "packet_count": 0,
            "byte_count": 0,
            "protocols": {},
            "ips": {},
            "ports": {}
        }
        
        # Determine best capture method
        self.capture_method = self._detect_capture_method()
        
        # Create output directory
        os.makedirs(self.config.get("pcap_output_dir", "output/captures"), exist_ok=True)
        
        self.logger.info(f"[TOOL] PacketCapture initialized with ID: {self.capture_id}")
        self.logger.info(f"[TOOL] Capture method: {self.capture_method}")

        #Default
        self.max_packets = self.config.get("max_packets", 10000)
    
    def _generate_capture_id(self) -> str:
        """Generate unique capture ID"""
        return f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for packet capture"""
        logger = logging.getLogger(f"PacketCapture.{self.capture_id}")
        if logger.handlers:
            return logger
        
        logger.setLevel(logging.DEBUG)
    
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Simple formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        try:
            fh = logging.FileHandler(f"logs/packet_capture_{self.capture_id}.log", encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"⚠️  Could not create log file: {e}")
        
        return logger
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        default_config = {
            "packet_capture": {
                "interface": None,  # None = auto-detect
                "capture_filter": "",
                "max_packets": 10000,
                "capture_timeout": 60,
                "pcap_output_dir": "output/captures",
                "buffer_size": 65536,
                "promiscuous_mode": False,
                "monitor_mode": False
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if "packet_capture" in config:
                        return config["packet_capture"]
                    return default_config["packet_capture"]
            else:
                print(f"[WARN] Config file not found at {config_path}, using defaults")
                return default_config["packet_capture"]
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return default_config["packet_capture"]
    
    def _detect_capture_method(self) -> str:
        """
        Detect the best available capture method for the current platform
        """
        if not SCAPY_AVAILABLE:
            return "unavailable"
        
        # Check if we can capture packets
        try:
            # Test capture for 1 packet (very quick)
            if IS_WINDOWS:
                # On Windows, check if Npcap is installed
                npcap_paths = [
                    r"C:\Windows\System32\Npcap",
                    r"C:\Program Files\Npcap",
                    r"C:\Program Files (x86)\Npcap"
                ]
                
                for path in npcap_paths:
                    if os.path.exists(path):
                        self.logger.info("[OK] Npcap found - packet capture available")
                        return "scapy_npcap"
                
                # Also check if we can import WinPcap/Npcap
                try:
                    from scapy.arch.windows import get_windows_if_list
                    interfaces = get_windows_if_list()
                    if interfaces:
                        self.logger.info("[OK] Windows packet capture available")
                        return "scapy_windows"
                except:
                    pass
                
                self.logger.warning("[WARN] Npcap not found. Install from: https://npcap.com")
                return "limited"
            else:
                # Linux/Unix - check for libpcap
                try:
                    # Quick test capture
                    conf.use_pcap = True
                    self.logger.info("[OK] libpcap found - packet capture available")
                    return "scapy_libpcap"
                except:
                    self.logger.warning("[WARN] libpcap not available")
                    return "limited"
        except Exception as e:
            self.logger.error(f"[ERROR] Capture detection failed: {e}")
            return "unavailable"
    
    def get_interfaces(self) -> List[Dict]:
        """
        Get list of available network interfaces
        """
        interfaces = []
        
        try:
            if SCAPY_AVAILABLE:
                if IS_WINDOWS:
                    try:
                        from scapy.arch.windows import get_windows_if_list
                        for iface in get_windows_if_list():
                            interfaces.append({
                                "name": iface.get("name", "Unknown"),
                                "description": iface.get("description", ""),
                                "ips": iface.get("ips", []),
                                "mac": iface.get("mac", "")
                            })
                    except:
                        pass
                else:
                    # Linux/Unix
                    from scapy.all import get_if_list
                    for iface_name in get_if_list():
                        interfaces.append({
                            "name": iface_name,
                            "description": iface_name,
                            "ips": [],
                            "mac": ""
                        })
            
            # If no interfaces found via Scapy, try psutil
            if not interfaces and PSUTIL_AVAILABLE:
                for name, addrs in psutil.net_if_addrs().items():
                    ips = [addr.address for addr in addrs if addr.family == 2]  # IPv4
                    interfaces.append({
                        "name": name,
                        "description": name,
                        "ips": ips,
                        "mac": ""
                    })
            
            self.logger.info(f"[NET] Found {len(interfaces)} network interfaces")
            
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to get interfaces: {e}")
        
        return interfaces
    
    def start_capture(self, 
                     interface: Optional[str] = None, 
                     bpf_filter: Optional[str] = None,
                     max_packets: Optional[int] = None,
                     timeout: Optional[int] = None) -> bool:
        """
        Start capturing packets in background thread
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("[ERROR] Scapy not available - cannot capture")
            return False
        
        if self.is_capturing:
            self.logger.warning("[WARN] Capture already in progress")
            return False
        
        # Reset state
        self.packets = []
        self.captured_bytes = 0
        self.stop_capture.clear()
        self.is_capturing = True
        
        # Set parameters
        self.capture_interface = interface or self.config.get("interface")
        self.capture_filter = bpf_filter or self.config.get("capture_filter", "")
        self.max_packets = max_packets or self.config.get("max_packets", 10000)
        self.capture_timeout = timeout or self.config.get("capture_timeout", 60)
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        self.logger.info(f"[START] Packet capture started")
        self.logger.info(f"         Interface: {self.capture_interface or 'Default'}")
        self.logger.info(f"         Filter: {self.capture_filter or 'None'}")
        self.logger.info(f"         Max packets: {self.max_packets}")
        self.logger.info(f"         Timeout: {self.capture_timeout}s")
        
        return True
    
    def _capture_packets(self):
        """
        Internal method that runs in thread to capture packets
        """
        self.stats["start_time"] = time.time()
        
        try:
            # Prepare sniff parameters
            sniff_kwargs = {
                "prn": self._packet_handler,
                "store": False,  # We store manually to track stats
                "timeout": self.capture_timeout,
                "stop_filter": lambda p: self.stop_capture.is_set()
            }
            
            # Add optional parameters
            if self.capture_interface:
                sniff_kwargs["iface"] = self.capture_interface
            
            if self.capture_filter:
                sniff_kwargs["filter"] = self.capture_filter
            
            if self.max_packets:
                sniff_kwargs["count"] = self.max_packets
            
            # Start sniffing (blocking call)
            sniff(**sniff_kwargs)
            
        except Exception as e:
            self.logger.error(f"[ERROR] Capture failed: {e}")
        
        finally:
            self.is_capturing = False
            self.stats["end_time"] = time.time()
            self.logger.info(f"[STOP] Capture stopped - {len(self.packets)} packets captured")
    
    def _packet_handler(self, packet):
        """
        Handle each captured packet
        """
        
        # Add to packet list
        self.packets.append(packet)
        
        # Update statistics
        try:
            packet_len = len(packet)
            self.captured_bytes += packet_len
            
            # Update protocol stats
            proto = self._get_protocol_name(packet)
            self.stats["protocols"][proto] = self.stats["protocols"].get(proto, 0) + 1
            
            # Update IP stats if present
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                self.stats["ips"][src_ip] = self.stats["ips"].get(src_ip, 0) + 1
                self.stats["ips"][dst_ip] = self.stats["ips"].get(dst_ip, 0) + 1
                
                # Update port stats for TCP/UDP
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    self.stats["ports"][sport] = self.stats["ports"].get(sport, 0) + 1
                    self.stats["ports"][dport] = self.stats["ports"].get(dport, 0) + 1
                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    self.stats["ports"][sport] = self.stats["ports"].get(sport, 0) + 1
                    self.stats["ports"][dport] = self.stats["ports"].get(dport, 0) + 1
            
        except Exception as e:
            self.logger.debug(f"Error updating stats: {e}")
        
        # Log every 100 packets
        if len(self.packets) % 100 == 0:
            elapsed = time.time() - self.stats["start_time"]
            rate = len(self.packets) / elapsed if elapsed > 0 else 0
            self.logger.info(f"[PROGRESS] Captured {len(self.packets)} packets ({rate:.1f} pkt/s)")
    
    def _get_protocol_name(self, packet) -> str:
        """Get protocol name from packet"""
        if IP in packet:
            proto_num = packet[IP].proto
            if proto_num == 6:
                return "TCP"
            elif proto_num == 17:
                return "UDP"
            elif proto_num == 1:
                return "ICMP"
            else:
                return f"IP-{proto_num}"
        elif IPv6 in packet:
            return "IPv6"
        elif ARP in packet:
            return "ARP"
        else:
            return "Other"
    
    def stop_capture_now(self):
        """Stop the ongoing capture"""
        if self.is_capturing:
            self.logger.info("[STOP] Stopping capture...")
            self.stop_capture.set()
            self.is_capturing = False
    
    def get_packets(self) -> List[Dict]:
        """
        Get captured packets in simplified dictionary format
        """
        packet_list = []
        
        for packet in self.packets:
            try:
                packet_dict = self._packet_to_dict(packet)
                if packet_dict:
                    packet_list.append(packet_dict)
            except Exception as e:
                self.logger.debug(f"Error converting packet: {e}")
        
        return packet_list
    
    def _packet_to_dict(self, packet) -> Optional[Dict]:
        """
        Convert Scapy packet to simplified dictionary
        """
        try:
            # Basic packet info
            packet_info = {
                "time": packet.time if hasattr(packet, 'time') else time.time(),
                "length": len(packet),
                "protocol": self._get_protocol_name(packet),
                "src": "0.0.0.0",
                "dst": "0.0.0.0",
                "sport": 0,
                "dport": 0,
                "info": "",
                "raw_data": None
            }
            
            # Extract IP information
            if IP in packet:
                packet_info["src"] = packet[IP].src
                packet_info["dst"] = packet[IP].dst
                
                # TCP
                if TCP in packet:
                    packet_info["protocol"] = "TCP"
                    packet_info["sport"] = packet[TCP].sport
                    packet_info["dport"] = packet[TCP].dport
                    packet_info["info"] = f"TCP {packet_info['sport']} -> {packet_info['dport']}"
                    
                    # Check for flags
                    flags = []
                    if packet[TCP].flags & 0x01:
                        flags.append("FIN")
                    if packet[TCP].flags & 0x02:
                        flags.append("SYN")
                    if packet[TCP].flags & 0x04:
                        flags.append("RST")
                    if packet[TCP].flags & 0x08:
                        flags.append("PSH")
                    if packet[TCP].flags & 0x10:
                        flags.append("ACK")
                    if flags:
                        packet_info["info"] += f" [{','.join(flags)}]"
                
                # UDP
                elif UDP in packet:
                    packet_info["protocol"] = "UDP"
                    packet_info["sport"] = packet[UDP].sport
                    packet_info["dport"] = packet[UDP].dport
                    packet_info["info"] = f"UDP {packet_info['sport']} -> {packet_info['dport']}"
                
                # ICMP
                elif ICMP in packet:
                    packet_info["protocol"] = "ICMP"
                    packet_info["info"] = f"ICMP type={packet[ICMP].type} code={packet[ICMP].code}"
            
            # IPv6
            elif IPv6 in packet:
                packet_info["src"] = packet[IPv6].src
                packet_info["dst"] = packet[IPv6].dst
                packet_info["protocol"] = "IPv6"
            
            # ARP
            elif ARP in packet:
                packet_info["protocol"] = "ARP"
                packet_info["info"] = f"ARP {packet[ARP].op} {packet[ARP].psrc} -> {packet[ARP].pdst}"
                packet_info["src"] = packet[ARP].psrc
                packet_info["dst"] = packet[ARP].pdst
            
            # DNS
            if DNS in packet and packet.haslayer(DNS):
                packet_info["protocol"] = "DNS"
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8', errors='ignore') if packet[DNSQR].qname else ""
                    packet_info["info"] = f"DNS Query: {qname}"
            
            # Raw data
            if Raw in packet:
                raw_data = bytes(packet[Raw].load)
                packet_info["raw_data"] = raw_data[:100]  # First 100 bytes only
                if not packet_info["info"]:
                    packet_info["info"] = f"Data ({len(raw_data)} bytes)"
            
            return packet_info
            
        except Exception as e:
            self.logger.debug(f"Packet conversion error: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """
        Get capture statistics
        """
        stats = self.stats.copy()
        
        if stats["start_time"]:
            duration = (stats.get("end_time") or time.time()) - stats["start_time"]
            stats["duration_seconds"] = round(duration, 2)
            
            if len(self.packets) > 0:
                stats["packets_per_second"] = round(len(self.packets) / duration, 2)
                stats["bytes_per_second"] = round(self.captured_bytes / duration, 2)
        
        stats["total_packets"] = len(self.packets)
        stats["total_bytes"] = self.captured_bytes
        stats["megabytes"] = round(self.captured_bytes / (1024 * 1024), 2)
        
        return stats
    
    def save_pcap(self, filename: Optional[str] = None) -> Optional[str]:
        """
        Save captured packets to PCAP file
        """
        if not self.packets:
            self.logger.warning("[WARN] No packets to save")
            return None
        
        # Generate filename if not provided
        if not filename:
            filename = f"{self.capture_id}.pcap"
        
        # Ensure .pcap extension
        if not filename.endswith('.pcap') and not filename.endswith('.pcapng'):
            filename += '.pcap'
        
        # Create full path
        output_dir = self.config.get("pcap_output_dir", "output/captures")
        filepath = os.path.join(output_dir, filename)
        
        try:
            wrpcap(filepath, self.packets)
            self.logger.info(f"[SAVE] Saved {len(self.packets)} packets to: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to save PCAP: {e}")
            return None
    
    def load_pcap(self, filepath: str) -> bool:
        """
        Load packets from PCAP file
        """
        if not os.path.exists(filepath):
            self.logger.error(f"[ERROR] PCAP file not found: {filepath}")
            return False
        
        try:
            self.packets = rdpcap(filepath)
            self.logger.info(f"[LOAD] Loaded {len(self.packets)} packets from: {filepath}")
            
            # Update statistics
            self.captured_bytes = sum(len(p) for p in self.packets)
            self.stats["start_time"] = time.time()
            
            return True
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to load PCAP: {e}")
            return False
    
    def get_packet_summary(self, max_packets: int = 10) -> List[Dict]:
        """
        Get a summary of recent packets
        """
        packets = self.get_packets()
        return packets[-max_packets:] if packets else []
    
    def filter_packets(self, 
                      protocol: Optional[str] = None,
                      src_ip: Optional[str] = None,
                      dst_ip: Optional[str] = None,
                      port: Optional[int] = None) -> List[Dict]:
        """
        Filter captured packets by criteria
        """
        packets = self.get_packets()
        filtered = []
        
        for p in packets:
            if protocol and p.get("protocol") != protocol:
                continue
            if src_ip and p.get("src") != src_ip:
                continue
            if dst_ip and p.get("dst") != dst_ip:
                continue
            if port and p.get("sport") != port and p.get("dport") != port:
                continue
            filtered.append(p)
        
        return filtered
    
    def cleanup(self):
        """Clean up capture resources"""
        self.stop_capture_now()
        
        # Clear packets to free memory
        self.packets = []
        self.captured_bytes = 0
        
        self.logger.info("[CLEAN] Packet capture cleaned up")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()


# Simple test function to generate test traffic
def generate_test_traffic(duration_seconds: int = 10):
    """
    Generate test network traffic for testing the packet capture
    """
    print(f"\n[TEST] Generating {duration_seconds}s of test traffic...")
    
    import socket
    import threading
    import time
    
    def udp_sender():
        """Send UDP packets to generate traffic"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(20):
                try:
                    message = f"Test packet {i}".encode()
                    sock.sendto(message, ("8.8.8.8", 53))
                    time.sleep(0.5)
                except Exception as e:
                    print(f"Socket error: {e}")
        finally:
            if sock:
                sock.close()
    
    def dns_simulator():
        """Simulate DNS queries"""
        domains = ["google.com", "example.com", "test.local", "malicious.evil"]
        for domain in domains:
            try:
                socket.gethostbyname(domain)
            except:
                pass
            time.sleep(0.3)
    
    # Start traffic generators
    threads = []
    for _ in range(3):
        t = threading.Thread(target=udp_sender)
        t.daemon = True
        t.start()
        threads.append(t)
    
    t = threading.Thread(target=dns_simulator)
    t.daemon = True
    t.start()
    threads.append(t)
    
    # Let traffic run
    time.sleep(duration_seconds)
    print("[TEST] Test traffic complete")


# Main test code
if __name__ == "__main__":
    print("=" * 60)
    print(" PACKET CAPTURE ENGINE TEST ")
    print("=" * 60)
    
    # Check if Scapy is available
    if not SCAPY_AVAILABLE:
        print("\n❌ Scapy is required for packet capture!")
        print("   Install with: pip install scapy")
        print("\n   Also on Windows, install Npcap from: https://npcap.com")
        sys.exit(1)
    
    # Test 1: Check interfaces
    print("\n[TEST 1] Listing network interfaces...")
    with PacketCapture() as capture:
        interfaces = capture.get_interfaces()
        if interfaces:
            for i, iface in enumerate(interfaces[:3]):  # Show first 3
                print(f"   {i+1}. {iface['name']}")
                if iface['ips']:
                    print(f"      IPs: {', '.join(iface['ips'][:2])}")
        else:
            print("   No interfaces found")
    
    # Test 2: Short capture test
    print("\n[TEST 2] Performing 10-second packet capture...")
    print("   (Will generate test traffic for analysis)")
    
    with PacketCapture() as capture:
        # Start capture in background
        success = capture.start_capture(timeout=15)
        
        if success:
            print("   Capture started, generating traffic...")
            
            # Generate test traffic in background
            traffic_thread = threading.Thread(
                target=generate_test_traffic,
                args=(8,)
            )
            traffic_thread.daemon = True
            traffic_thread.start()
            
            # Wait for capture to complete
            try:
                time.sleep(12)
            except KeyboardInterrupt:
                print("\n[INFO] Capture interrupted by user")
                capture.stop_capture_now()
            
            # Stop capture
            capture.stop_capture_now()
            time.sleep(1)
            
            # Show results
            stats = capture.get_statistics()
            print(f"\n[RESULTS]")
            print(f"   Packets captured: {stats['total_packets']}")
            print(f"   Data volume: {stats['megabytes']} MB")
            print(f"   Duration: {stats.get('duration_seconds', 0):.1f}s")
            
            if stats['total_packets'] > 0:
                print(f"   Rate: {stats.get('packets_per_second', 0):.1f} pkt/s")
            
            # Show protocol breakdown
            if stats['protocols']:
                print(f"\n   Protocols:")
                for proto, count in list(stats['protocols'].items())[:5]:
                    pct = (count / stats['total_packets']) * 100
                    print(f"      {proto}: {count} ({pct:.1f}%)")
            
            # Show sample packets
            packets = capture.get_packet_summary(5)
            if packets:
                print(f"\n   Recent packets:")
                for i, p in enumerate(packets):
                    print(f"      {p['time']:.2f}: {p['protocol']} {p['src']}:{p['sport']} -> {p['dst']}:{p['dport']} - {p.get('info', '')[:50]}")
            
            # Save to PCAP
            pcap_file = capture.save_pcap()
            if pcap_file:
                print(f"\n   Saved to: {pcap_file}")
    
    print("\n" + "=" * 60)
    print(" TEST COMPLETE ")
    print("=" * 60)