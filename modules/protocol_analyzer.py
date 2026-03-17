"""
Module 3: Protocol Analyzer
Analyzes captured traffic to identify protocols, detect anomalies, and spot malicious patterns
"""

import os
import sys
import json
import math
import time
import struct
import socket
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
import logging


# Try to import numpy for statistical analysis
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️  NumPy not installed. Run: pip install numpy")


# Import packet capture if available
try:
    from modules.packet_capture import PacketCapture
    PACKET_CAPTURE_AVAILABLE = True
except ImportError:
    PACKET_CAPTURE_AVAILABLE = False

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'


class ProtocolAnalyzer:
    """
    Analyzes network traffic to identify protocols and detect anomalies
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the protocol analyzer
        """
        self.analysis_id = self._generate_analysis_id()
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Analysis results
        self.packets = []
        self.protocols_detected = {}
        self.flows = {}
        self.alerts = []
        self.anomalies = []
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "unique_ips": set(),
            "unique_domains": set(),
            "protocol_counts": Counter(),
            "port_counts": Counter(),
            "packet_sizes": [],
            "inter_arrival_times": []
        }
        
        # Detection thresholds from config
        self.entropy_threshold = self.config.get("entropy_threshold", 0.8)
        self.suspicious_ports = self.config.get("suspicious_ports", 
                                               [22, 23, 53, 445, 3389, 4444, 5555, 6667, 8080, 8443])
        self.dns_tunneling_threshold = self.config.get("dns_tunneling_threshold", 0.7)
        
        # Create output directory
        os.makedirs("output/analysis", exist_ok=True)
        
        self.logger.info(f"[TOOL] ProtocolAnalyzer initialized with ID: {self.analysis_id}")
    
    def _generate_analysis_id(self) -> str:
        """Generate unique analysis ID"""
        return f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for protocol analyzer"""
        logger = logging.getLogger(f"ProtocolAnalyzer.{self.analysis_id}")
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
            fh = logging.FileHandler(f"logs/protocol_analysis_{self.analysis_id}.log", encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"⚠️  Could not create log file: {e}")
        
        return logger
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        default_config = {
            "entropy_threshold": 0.8,
            "suspicious_ports": [22, 23, 53, 445, 3389, 4444, 5555, 6667, 8080, 8443],
            "known_malicious_domains": [],
            "dns_tunneling_threshold": 0.7,
            "c2_beacon_threshold": 0.6,
            "packet_size_variance_threshold": 50,
            "timing_analysis_window": 10,
            "protocol_signatures": {
                "HTTP": [b"HTTP/", b"GET ", b"POST ", b"PUT ", b"DELETE "],
                "DNS": [b"\x00\x01\x00\x00", b"\x00\x00\x01\x00\x01"],  # DNS query patterns
                "SMB": [b"\xff\x53\x4d\x42"],  # SMB marker
                "TLS": [b"\x16\x03", b"\x17\x03"],  # TLS handshake/application
                "SSH": [b"SSH-"],
                "FTP": [b"220 ", b"USER ", b"PASS "]
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if "protocol_analysis" in config:
                        return config["protocol_analysis"]
                    return default_config
            else:
                print(f"[WARN] Config file not found at {config_path}, using defaults")
                return default_config
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return default_config
    
    def load_packets(self, packets):
        """
        Load packets for analysis (can be from capture or file)
        """
        self.packets = packets
        self.stats["total_packets"] = len(packets)
        self.logger.info(f"[LOAD] Loaded {len(packets)} packets for analysis")
        
        # Calculate total bytes
        total_bytes = 0
        for packet in packets:
            if hasattr(packet, 'len') or (isinstance(packet, dict) and 'length' in packet):
                length = packet.len if hasattr(packet, 'len') else packet['length']
                total_bytes += length
        self.stats["total_bytes"] = total_bytes
    
    def analyze(self):
        """
        Perform comprehensive protocol analysis
        """
        self.logger.info("[ANALYZE] Starting protocol analysis...")
        self.stats["start_time"] = time.time()
        
        if not self.packets:
            self.logger.warning("[WARN] No packets to analyze")
            return {}
        
        # Run all analysis modules
        self._identify_protocols()
        self._reconstruct_flows()
        self._analyze_entropy()
        self._detect_dns_tunneling()
        self._detect_c2_beacons()
        self._analyze_packet_sizes()
        self._check_suspicious_ports()
        self._analyze_timing()
        self._detect_http_anomalies()
        
        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        self.logger.info(f"[COMPLETE] Analysis completed in {duration:.2f}s")
        self.logger.info(f"           Protocols detected: {len(self.protocols_detected)}")
        self.logger.info(f"           Flows reconstructed: {len(self.flows)}")
        self.logger.info(f"           Alerts generated: {len(self.alerts)}")
        
        return self.get_results()
    
    def _identify_protocols(self):
        """
        Identify protocols used in the traffic
        """
        self.logger.info("[PROTO] Identifying protocols...")
        
        protocol_signatures = self.config.get("protocol_signatures", {})
        
        for i, packet in enumerate(self.packets):
            # Get packet data based on format
            if hasattr(packet, 'original'):  # Scapy packet
                packet_data = bytes(packet.original)
                proto = self._get_packet_protocol(packet)
            elif isinstance(packet, dict):  # Dictionary format
                packet_data = packet.get('raw_data', b'')
                if isinstance(packet_data, str):
                    packet_data = packet_data.encode('utf-8', errors='ignore')
                proto = packet.get('protocol', 'Unknown')
            else:
                continue
            
            # Count protocol
            self.stats["protocol_counts"][proto] += 1
            
            # Deep protocol inspection
            detected_protocols = []
            
            # Check against signatures
            for protocol, signatures in protocol_signatures.items():
                for sig in signatures:
                    if isinstance(sig, str):
                        sig = sig.encode('utf-8', errors='ignore')
                    if sig in packet_data:
                        detected_protocols.append(protocol)
                        break
            
            # Protocol-specific detection
            if proto == "TCP" or proto == "UDP":
                # Check port-based protocols
                if isinstance(packet, dict):
                    sport = packet.get('sport', 0)
                    dport = packet.get('dport', 0)
                    
                    # Common protocol ports
                    if dport == 80 or sport == 80:
                        detected_protocols.append("HTTP")
                    elif dport == 443 or sport == 443:
                        detected_protocols.append("HTTPS")
                    elif dport == 53 or sport == 53:
                        detected_protocols.append("DNS")
                    elif dport == 22 or sport == 22:
                        detected_protocols.append("SSH")
                    elif dport == 21 or sport == 21:
                        detected_protocols.append("FTP")
                    elif dport == 25 or sport == 25:
                        detected_protocols.append("SMTP")
                    elif dport == 445 or sport == 445:
                        detected_protocols.append("SMB")
            
            # Update protocol detection
            for detected in detected_protocols:
                if detected not in self.protocols_detected:
                    self.protocols_detected[detected] = {
                        "count": 0,
                        "packets": [],
                        "confidence": 0.5
                    }
                self.protocols_detected[detected]["count"] += 1
                if len(self.protocols_detected[detected]["packets"]) < 10:  # Store sample packets
                    self.protocols_detected[detected]["packets"].append(i)
            
            # TRACK UNIQUE IPS AND DOMAINS - Fixed indentation (now at same level as other packet processing)
            if isinstance(packet, dict):
                src = packet.get('src', '')
                dst = packet.get('dst', '')
                if src and src != '0.0.0.0':
                    self.stats["unique_ips"].add(src)
                if dst and dst != '0.0.0.0':
                    self.stats["unique_ips"].add(dst)
                
                # For domains (if DNS packet)
                if packet.get('protocol') == 'DNS':
                    info = packet.get('info', '')
                    if 'Query:' in info:
                        domain = info.split('Query:')[-1].strip()
                        self.stats["unique_domains"].add(domain)
        
        # Calculate confidence for each protocol
        for protocol, data in self.protocols_detected.items():
            confidence = min(1.0, data["count"] / 10)  # Simple confidence based on count
            data["confidence"] = round(confidence, 2)
    
    def _get_packet_protocol(self, packet):
        """Extract protocol from packet"""
        if hasattr(packet, 'haslayer'):
            if packet.haslayer('TCP'):
                return "TCP"
            elif packet.haslayer('UDP'):
                return "UDP"
            elif packet.haslayer('ICMP'):
                return "ICMP"
            elif packet.haslayer('ARP'):
                return "ARP"
            elif packet.haslayer('DNS'):
                return "DNS"
            else:
                return "Other"
        return "Unknown"
    def _reconstruct_flows(self):
        """
        Reconstruct TCP/UDP flows from packets
        """
        self.logger.info("[FLOWS] Reconstructing communication flows...")
        
        flows = {}
        
        for i, packet in enumerate(self.packets):
            # Skip non-dictionary packets (like raw Scapy packets)
            if not isinstance(packet, dict):
                continue
            
            # Extract packet data (dictionary format)
            src = packet.get('src', '0.0.0.0')
            dst = packet.get('dst', '0.0.0.0')
            sport = packet.get('sport', 0)
            dport = packet.get('dport', 0)
            proto = packet.get('protocol', 'Unknown')
            time_val = packet.get('time', 0)
            length = packet.get('length', 0)
            
            # Create flow key (bidirectional - consistent regardless of direction)
            # Sort IPs to ensure same flow key for both directions
            if src < dst:
                flow_key = f"{proto}_{src}:{sport}-{dst}:{dport}"
            else:
                flow_key = f"{proto}_{dst}:{dport}-{src}:{sport}"
            
            # Initialize flow if new
            if flow_key not in flows:
                flows[flow_key] = {
                    "protocol": proto,
                    "src_ip": src,
                    "src_port": sport,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "packet_indices": [],
                    "bytes": 0,
                    "start_time": time_val,
                    "end_time": time_val,
                    "packet_count": 0,
                    "byte_count": 0,
                    "packet_sizes": [],
                    "intervals": []
                }
            
            # Update flow
            flow = flows[flow_key]
            flow["packet_indices"].append(i)
            flow["packet_count"] += 1
            flow["byte_count"] += length
            flow["packet_sizes"].append(length)
            
            # Update timestamps
            if time_val < flow["start_time"]:
                flow["start_time"] = time_val
            if time_val > flow["end_time"]:
                flow["end_time"] = time_val
            
            # Calculate interval if this isn't the first packet
            if len(flow["packet_indices"]) > 1:
                # Use previous packet's time for interval
                prev_packet_index = flow["packet_indices"][-2]
                prev_packet = self.packets[prev_packet_index]
                prev_time = prev_packet.get('time', 0) if isinstance(prev_packet, dict) else 0
                
                if prev_time > 0:
                    interval = time_val - prev_time
                    if interval > 0:  # Only add positive intervals
                        flow["intervals"].append(interval)
        
        self.flows = flows
        self.logger.info(f"[FLOWS] Reconstructed {len(flows)} unique flows")
    
    def _analyze_entropy(self):
        """
        Calculate entropy for packet payloads to detect encrypted/obfuscated traffic
        """
        self.logger.info("[ENTROPY] Analyzing payload entropy...")
        
        high_entropy_packets = []
        
        for i, packet in enumerate(self.packets):
            # Extract payload
            payload = b''
            
            if hasattr(packet, 'original'):  # Scapy packet
                if hasattr(packet, 'payload'):
                    payload = bytes(packet.payload)
            elif isinstance(packet, dict):  # Dictionary format
                raw = packet.get('raw_data', b'')
                if isinstance(raw, str):
                    payload = raw.encode('utf-8', errors='ignore')
                else:
                    payload = raw
            
            if len(payload) < 20:  # Skip very small payloads
                continue
            
            # Calculate Shannon entropy
            entropy = self._calculate_entropy(payload)
            
            # Check if entropy exceeds threshold
            if entropy > self.entropy_threshold:
                high_entropy_packets.append({
                    "packet_index": i,
                    "entropy": round(entropy, 3),
                    "length": len(payload),
                    "protocol": packet.get('protocol', 'Unknown') if isinstance(packet, dict) else 'Unknown'
                })
        
        if high_entropy_packets:
            alert = {
                "type": "high_entropy_traffic",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "packet_count": len(high_entropy_packets),
                    "average_entropy": sum(p["entropy"] for p in high_entropy_packets) / len(high_entropy_packets),
                    "samples": high_entropy_packets[:5]  # First 5 samples
                },
                "description": f"Detected {len(high_entropy_packets)} packets with high entropy (possible encryption/obfuscation)"
            }
            self.alerts.append(alert)
            self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _calculate_entropy(self, data):
        """
        Calculate Shannon entropy of data
        """
        if not data:
            return 0
        
        entropy = 0
        data_len = len(data)
        
        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_dns_tunneling(self):
        """
        Detect possible DNS tunneling (data exfiltration over DNS)
        """
        self.logger.info("[DNS] Checking for DNS tunneling...")
        
        dns_queries = []
        
        for i, packet in enumerate(self.packets):
            # Check if this is a DNS packet
            proto = packet.get('protocol', '') if isinstance(packet, dict) else ''
            if proto != "DNS" and "DNS" not in str(packet):
                continue
            
            # Extract DNS query
            query = ""
            if isinstance(packet, dict):
                info = packet.get('info', '')
                if "Query:" in info:
                    query = info.split("Query:")[-1].strip()
                elif "DNS" in info:
                    query = info
            else:
                # Try to extract from string representation
                packet_str = str(packet)
                if "DNS" in packet_str and "Query" in packet_str:
                    # Simple extraction - in production you'd parse properly
                    query = packet_str
            
            if query:
                dns_queries.append({
                    "packet_index": i,
                    "query": query,
                    "length": len(query)
                })
        
        # Analyze DNS queries for tunneling
        suspicious_queries = []
        
        for query in dns_queries:
            query_str = query["query"]
            query_len = query["length"]
            
            # Check for long queries (potential tunneling)
            if query_len > 50:
                # Calculate entropy of domain name
                domain_bytes = query_str.encode('utf-8', errors='ignore')
                entropy = self._calculate_entropy(domain_bytes)
                
                # High entropy + long query = suspicious
                if entropy > 0.8:
                    suspicious_queries.append({
                        **query,
                        "entropy": round(entropy, 3),
                        "reason": "long_query_high_entropy"
                    })
                else:
                    suspicious_queries.append({
                        **query,
                        "entropy": round(entropy, 3),
                        "reason": "long_query"
                    })
            
            # Check for subdomain pattern (many subdomains)
            if query_str.count('.') > 5:
                suspicious_queries.append({
                    **query,
                    "reason": "excessive_subdomains"
                })
            
            # Check for base64-like characters
            base64_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=')
            if all(c in base64_chars or c == '.' for c in query_str.replace('.', '')[:20]):
                suspicious_queries.append({
                    **query,
                    "reason": "base64_pattern"
                })
        
        if suspicious_queries:
            # Deduplicate by packet index
            unique_suspicious = {}
            for q in suspicious_queries:
                unique_suspicious[q["packet_index"]] = q
            
            alert = {
                "type": "possible_dns_tunneling",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "total_dns_queries": len(dns_queries),
                    "suspicious_queries": len(unique_suspicious),
                    "samples": list(unique_suspicious.values())[:5]
                },
                "description": f"Detected {len(unique_suspicious)} suspicious DNS queries (possible tunneling)"
            }
            self.alerts.append(alert)
            self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_c2_beacons(self):
        """
        Detect command and control beacon patterns
        """
        self.logger.info("[C2] Checking for C2 beacon patterns...")
        
        for flow_key, flow in self.flows.items():
            if flow["packet_count"] < 5:  # Need enough packets
                continue
            
            # Analyze packet intervals
            intervals = flow.get("intervals", [])
            if len(intervals) < 3:
                continue
            
            if NUMPY_AVAILABLE:
                # Calculate statistics
                intervals_array = np.array(intervals)
                mean_interval = np.mean(intervals_array)
                std_interval = np.std(intervals_array)
                
                # Check for regular intervals (low standard deviation)
                if std_interval < 0.5 and mean_interval > 0:
                    cv = std_interval / mean_interval  # Coefficient of variation
                    
                    if cv < 0.3:  # Very regular
                        alert = {
                            "type": "c2_beacon_detected",
                            "severity": "high",
                            "timestamp": time.time(),
                            "details": {
                                "flow": flow_key,
                                "src_ip": flow["src_ip"],
                                "dst_ip": flow["dst_ip"],
                                "dst_port": flow["dst_port"],
                                "packet_count": flow["packet_count"],
                                "mean_interval": round(mean_interval, 3),
                                "std_interval": round(std_interval, 3),
                                "cv": round(cv, 3)
                            },
                            "description": f"Regular beacon pattern detected to {flow['dst_ip']}:{flow['dst_port']}"
                        }
                        self.alerts.append(alert)
                        self.logger.warning(f"[ALERT] {alert['description']}")
            
            # Jitter analysis (even without numpy)
            elif len(intervals) >= 5:
                # Simple variance calculation
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                std_interval = math.sqrt(variance)
                
                if mean_interval > 0:
                    cv = std_interval / mean_interval
                    if cv < 0.4:
                        self.logger.info(f"[C2] Possible beacon in flow {flow_key} (CV={cv:.3f})")
    
    def _analyze_packet_sizes(self):
        """
        Analyze packet size distributions for anomalies
        """
        self.logger.info("[SIZE] Analyzing packet size patterns...")
        
        # Collect packet sizes
        packet_sizes = []
        for packet in self.packets:
            if isinstance(packet, dict):
                size = packet.get('length', 0)
            else:
                size = len(packet) if hasattr(packet, '__len__') else 0
            if size > 0:
                packet_sizes.append(size)
        
        if not packet_sizes:
            return
        
        self.stats["packet_sizes"] = packet_sizes
        
        # Calculate statistics
        if NUMPY_AVAILABLE:
            sizes_array = np.array(packet_sizes)
            mean_size = np.mean(sizes_array)
            std_size = np.std(sizes_array)
            median_size = np.median(sizes_array)
            
            # Check for unusual size patterns
            unusual_sizes = sizes_array[sizes_array > mean_size + 3 * std_size]
            
            if len(unusual_sizes) > 0:
                # Could be data exfiltration or covert channel
                alert = {
                    "type": "unusual_packet_sizes",
                    "severity": "medium",
                    "timestamp": time.time(),
                    "details": {
                        "unusual_packets": len(unusual_sizes),
                        "mean_size": round(mean_size, 2),
                        "std_size": round(std_size, 2),
                        "max_size": int(np.max(sizes_array)),
                        "min_size": int(np.min(sizes_array))
                    },
                    "description": f"Detected {len(unusual_sizes)} packets with unusual size (possible covert channel)"
                }
                self.alerts.append(alert)
        
        # Look for fixed-size packets (potential covert channel)
        size_counts = Counter(packet_sizes)
        fixed_size_alerts = []
        
        for size, count in size_counts.items():
            if count > len(packet_sizes) * 0.3 and count > 10:  # >30% packets same size
                fixed_size_alerts.append({"size": size, "count": count})
        
        if fixed_size_alerts:
            alert = {
                "type": "fixed_packet_sizes",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "fixed_sizes": fixed_size_alerts[:5],
                    "total_packets": len(packet_sizes)
                },
                "description": f"Detected many packets with identical size (possible covert channel)"
            }
            self.alerts.append(alert)
    
    def _check_suspicious_ports(self):
        """
        Check for traffic on suspicious ports
        """
        self.logger.info("[PORTS] Checking for suspicious port usage...")
        
        suspicious_traffic = []
        
        for packet in self.packets:
            if isinstance(packet, dict):
                dport = packet.get('dport', 0)
                sport = packet.get('sport', 0)
                proto = packet.get('protocol', '')
                
                # Check if destination port is suspicious
                if dport in self.suspicious_ports:
                    suspicious_traffic.append({
                        "protocol": proto,
                        "src": packet.get('src', ''),
                        "dst": packet.get('dst', ''),
                        "port": dport,
                        "direction": "outbound"
                    })
                
                # Check if source port is suspicious
                if sport in self.suspicious_ports and sport != dport:
                    suspicious_traffic.append({
                        "protocol": proto,
                        "src": packet.get('src', ''),
                        "dst": packet.get('dst', ''),
                        "port": sport,
                        "direction": "inbound"
                    })
        
        if suspicious_traffic:
            # Group by port
            port_groups = {}
            for t in suspicious_traffic:
                port = t["port"]
                if port not in port_groups:
                    port_groups[port] = []
                port_groups[port].append(t)
            
            alert = {
                "type": "suspicious_port_usage",
                "severity": "low",
                "timestamp": time.time(),
                "details": {
                    "ports": {p: len(traffic) for p, traffic in port_groups.items()},
                    "samples": suspicious_traffic[:5]
                },
                "description": f"Traffic detected on suspicious ports: {', '.join(str(p) for p in port_groups.keys())}"
            }
            self.alerts.append(alert)
            self.logger.info(f"[PORTS] {alert['description']}")
    
    def _analyze_timing(self):
        """
        Analyze packet timing patterns
        """
        self.logger.info("[TIMING] Analyzing packet timing patterns...")
        
        # Extract timestamps
        timestamps = []
        for packet in self.packets:
            if isinstance(packet, dict):
                ts = packet.get('time', 0)
            else:
                ts = getattr(packet, 'time', 0)
            if ts > 0:
                timestamps.append(ts)
        
        if len(timestamps) < 5:
            return
        
        # Sort timestamps
        timestamps.sort()
        
        # Calculate inter-arrival times
        inter_arrivals = []
        for i in range(1, len(timestamps)):
            inter_arrivals.append(timestamps[i] - timestamps[i-1])
        
        self.stats["inter_arrival_times"] = inter_arrivals
        
        # Look for timing patterns
        if NUMPY_AVAILABLE and len(inter_arrivals) > 10:
            intervals = np.array(inter_arrivals)
            
            # Check for periodic bursts
            # Simple FFT would be better, but this is a basic check
            unique_intervals = set(round(i, 3) for i in intervals if i > 0)
            
            if len(unique_intervals) < len(intervals) * 0.2:  # Many repeating intervals
                alert = {
                    "type": "timing_pattern",
                    "severity": "medium",
                    "timestamp": time.time(),
                    "details": {
                        "unique_intervals": len(unique_intervals),
                        "total_intervals": len(intervals),
                        "suspicious_ratio": round(len(unique_intervals) / len(intervals), 3)
                    },
                    "description": "Detected repeating packet intervals (possible timing-based covert channel)"
                }
                self.alerts.append(alert)
    
    def _detect_http_anomalies(self):
        """
        Detect anomalies in HTTP traffic
        """
        self.logger.info("[HTTP] Checking for HTTP anomalies...")
        
        http_packets = []
        
        for packet in self.packets:
            if isinstance(packet, dict):
                proto = packet.get('protocol', '')
                info = packet.get('info', '')
                
                if proto == "HTTP" or "HTTP" in info or info.startswith(('GET ', 'POST ', 'PUT ')):
                    http_packets.append(packet)
        
        if not http_packets:
            return
        
        # Check for suspicious HTTP methods
        suspicious_methods = ['PUT', 'DELETE', 'CONNECT', 'TRACE']
        found_methods = []
        
        for packet in http_packets:
            info = packet.get('info', '')
            for method in suspicious_methods:
                if info.startswith(method):
                    found_methods.append({"method": method, "info": info[:50]})
        
        if found_methods:
            alert = {
                "type": "suspicious_http_method",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "methods": found_methods[:5]
                },
                "description": f"Detected suspicious HTTP methods: {', '.join(set(m['method'] for m in found_methods))}"
            }
            self.alerts.append(alert)
        
        # Check for long URIs (potential data exfiltration)
        long_uris = []
        for packet in http_packets:
            info = packet.get('info', '')
            if len(info) > 200:  # Long URI/request line
                long_uris.append({"info": info[:100] + "...", "length": len(info)})
        
        if long_uris:
            alert = {
                "type": "long_http_uri",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "samples": long_uris[:3]
                },
                "description": f"Detected {len(long_uris)} unusually long HTTP URIs"
            }
            self.alerts.append(alert)
    
    def get_results(self):
        """
        Get complete analysis results
        """
        # Convert sets to lists for JSON serialization
        stats_serializable = dict(self.stats)
        stats_serializable["unique_ips"] = list(self.stats["unique_ips"])
        stats_serializable["unique_domains"] = list(self.stats["unique_domains"])
        stats_serializable["protocol_counts"] = dict(self.stats["protocol_counts"])
        stats_serializable["port_counts"] = dict(self.stats["port_counts"])
        
        
        # Convert NumPy arrays if present
        if NUMPY_AVAILABLE:
            if isinstance(self.stats["packet_sizes"], np.ndarray):
                stats_serializable["packet_sizes"] = self.stats["packet_sizes"].tolist()
            if isinstance(self.stats["inter_arrival_times"], np.ndarray):
                stats_serializable["inter_arrival_times"] = self.stats["inter_arrival_times"].tolist()
        else:
            stats_serializable["packet_sizes"] = list(self.stats["packet_sizes"])
            stats_serializable["inter_arrival_times"] = list(self.stats["inter_arrival_times"])
        
        return {
            "analysis_id": self.analysis_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": stats_serializable,
            "protocols": self.protocols_detected,
            "alerts": self.alerts,
            "anomalies": self.anomalies,
            "flow_count": len(self.flows)
        }
    
    def generate_report(self, format="json"):
        """
        Generate analysis report
        """
        results = self.get_results()
        
        if format == "json":
            report_file = f"output/analysis/{self.analysis_id}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"[REPORT] JSON report saved to: {report_file}")
            return report_file
        
        elif format == "text":
            # Generate text summary
            lines = []
            lines.append("=" * 60)
            lines.append(f"PROTOCOL ANALYSIS REPORT - {self.analysis_id}")
            lines.append("=" * 60)
            lines.append("")
            
            # Statistics
            lines.append("📊 STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Total Packets: {self.stats['total_packets']}")
            lines.append(f"Total Bytes: {self.stats['total_bytes']} ({self.stats['total_bytes']/1024/1024:.2f} MB)")
            lines.append(f"Unique IPs: {len(self.stats['unique_ips'])}")
            lines.append(f"Unique Domains: {len(self.stats['unique_domains'])}")
            lines.append("")
            
            # Protocols
            lines.append("📡 PROTOCOLS DETECTED")
            lines.append("-" * 40)
            for proto, count in self.stats["protocol_counts"].most_common(10):
                pct = (count / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
                lines.append(f"  {proto}: {count} ({pct:.1f}%)")
            lines.append("")
            
            # Alerts
            lines.append("🚨 ALERTS")
            lines.append("-" * 40)
            if self.alerts:
                for alert in self.alerts:
                    severity_symbol = {
                        "high": "🔴",
                        "medium": "🟡",
                        "low": "🟢"
                    }.get(alert["severity"], "⚪")
                    lines.append(f"{severity_symbol} [{alert['severity'].upper()}] {alert['type']}")
                    lines.append(f"   {alert['description']}")
                    lines.append("")
            else:
                lines.append("  No alerts generated")
            lines.append("")
            
            # Flows
            lines.append("🔄 TOP FLOWS")
            lines.append("-" * 40)
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1]["packet_count"], reverse=True)[:5]
            for flow_key, flow in sorted_flows:
                lines.append(f"  {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}")
                lines.append(f"     Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}")
            lines.append("")
            
            lines.append("=" * 60)
            
            report_text = "\n".join(lines)
            
            # Save to file
            report_file = f"output/analysis/analysis_{self.analysis_id}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            
            self.logger.info(f"[REPORT] Text report saved to: {report_file}")
            return report_file
        
        return results
    
    def get_alerts_summary(self):
        """
        Get summary of all alerts
        """
        return {
            "total_alerts": len(self.alerts),
            "by_severity": {
                "high": sum(1 for a in self.alerts if a["severity"] == "high"),
                "medium": sum(1 for a in self.alerts if a["severity"] == "medium"),
                "low": sum(1 for a in self.alerts if a["severity"] == "low")
            },
            "by_type": dict(Counter(a["type"] for a in self.alerts)),
            "alerts": self.alerts
        }
    
    def cleanup(self):
        """
        Clean up analyzer resources
        """
        self.packets = []
        self.flows = {}
        self.alerts = []
        self.logger.info("[CLEAN] Protocol analyzer cleaned up")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()


# Test function
def test_analyzer():
    """
    Test the protocol analyzer with sample data
    """
    print("=" * 60)
    print(" PROTOCOL ANALYZER TEST ")
    print("=" * 60)
    
    # Create sample packets (simulating what we'd get from packet capture)
    sample_packets = []
    
    # Normal HTTP traffic
    sample_packets.append({
        "time": time.time(),
        "length": 450,
        "protocol": "TCP",
        "src": "192.168.1.100",
        "dst": "93.184.216.34",
        "sport": 54321,
        "dport": 80,
        "info": "GET /index.html HTTP/1.1",
        "raw_data": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    })
    
    # Normal DNS query
    sample_packets.append({
        "time": time.time() + 0.1,
        "length": 80,
        "protocol": "DNS",
        "src": "192.168.1.100",
        "dst": "8.8.8.8",
        "sport": 12345,
        "dport": 53,
        "info": "DNS Query: google.com",
        "raw_data": b""
    })
    
    # Suspicious DNS tunneling attempt
    long_domain = "a" * 60 + ".b" * 30 + ".com"
    sample_packets.append({
        "time": time.time() + 0.2,
        "length": 150,
        "protocol": "DNS",
        "src": "192.168.1.100",
        "dst": "8.8.8.8",
        "sport": 12346,
        "dport": 53,
        "info": f"DNS Query: {long_domain}",
        "raw_data": long_domain.encode()
    })
    
    # C2 beacon pattern (regular intervals)
    for i in range(10):
        sample_packets.append({
            "time": time.time() + 10 + i * 5.01,  # ~5 second intervals
            "length": 100,
            "protocol": "TCP",
            "src": "192.168.1.100",
            "dst": "45.33.22.11",
            "sport": 44444,
            "dport": 4444,  # Suspicious port
            "info": f"Data packet {i}",
            "raw_data": b"\x01" * 100
        })
    
    # High entropy traffic (encrypted/obfuscated)
    import random
    high_entropy_data = bytes([random.randint(0, 255) for _ in range(200)])
    sample_packets.append({
        "time": time.time() + 15,
        "length": 250,
        "protocol": "UDP",
        "src": "192.168.1.100",
        "dst": "203.0.113.5",
        "sport": 33333,
        "dport": 12345,
        "info": "UDP Data",
        "raw_data": high_entropy_data
    })
    
    # Fixed size packets (covert channel)
    for i in range(5):
        sample_packets.append({
            "time": time.time() + 20 + i,
            "length": 64,  # Same size
            "protocol": "ICMP",
            "src": "192.168.1.100",
            "dst": "8.8.8.8",
            "sport": 0,
            "dport": 0,
            "info": f"ICMP Echo {i}",
            "raw_data": b"A" * 64
        })
    
    # Run analysis
    print("\n[TEST] Running protocol analysis...")
    
    analyzer = ProtocolAnalyzer()
    analyzer.load_packets(sample_packets)
    results = analyzer.analyze()
    
    # Display results
    print(f"\n[RESULTS]")
    print(f"   Packets analyzed: {results['statistics']['total_packets']}")
    print(f"   Protocols detected: {len(results['protocols'])}")
    print(f"   Alerts generated: {len(results['alerts'])}")
    
    # Show alerts
    if results['alerts']:
        print(f"\n   ALERTS:")
        for alert in results['alerts']:
            severity_symbol = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢"
            }.get(alert["severity"], "⚪")
            print(f"      {severity_symbol} [{alert['severity'].upper()}] {alert['type']}")
            print(f"         {alert['description']}")
    
    # Generate report
    report_file = analyzer.generate_report("text")
    print(f"\n   Report saved to: {report_file}")
    
    print("\n" + "=" * 60)
    print(" TEST COMPLETE ")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    test_analyzer()