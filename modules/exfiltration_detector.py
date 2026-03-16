"""
Module 4: Exfiltration Detector
Detects data theft attempts, covert channels, and information leakage
"""

import os
import sys
import json
import math
import time
import struct
import hashlib
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path
import logging

# Try to import image processing for steganography detection
try:
    from PIL import Image
    import PIL.ImageOps
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("⚠️  PIL not installed. Run: pip install pillow")

# Try to import numpy for statistical analysis
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️  NumPy not installed. Run: pip install numpy")

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'


class ExfiltrationDetector:
    """
    Detects data exfiltration attempts and covert channels in network traffic
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the exfiltration detector
        """
        self.detector_id = self._generate_detector_id()
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Detection results
        self.packets = []
        self.alerts = []
        self.suspicious_flows = {}
        self.exfiltration_events = []
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "total_flows": 0,
            "start_time": None,
            "end_time": None,
            "bytes_by_destination": defaultdict(int),
            "packets_by_size": Counter(),
            "flows_by_protocol": Counter()
        }
        
        # Detection thresholds from config
        self.data_rate_threshold = self.config.get("data_rate_threshold_kbps", 100)  # KB/s
        self.packet_size_variance_threshold = self.config.get("packet_size_variance_threshold", 50)
        self.timing_analysis_window = self.config.get("timing_analysis_window", 10)
        self.steganography_check = self.config.get("steganography_check", True)
        self.suspicious_extensions = self.config.get("suspicious_extensions", 
                                                    [".jpg", ".png", ".zip", ".rar", ".docx", ".pdf"])
        
        # Known sensitive data patterns
        self.sensitive_patterns = [
            b"password", b"username", b"credit card", b"ssn", b"social security",
            b"secret", b"confidential", b"api_key", b"token", b"authorization",
            b"bearer", b"jwt", b"private key", b"certificate", b"passphrase"
        ]
        
        # Create output directory
        os.makedirs("output/exfiltration", exist_ok=True)
        
        self.logger.info(f"[TOOL] ExfiltrationDetector initialized with ID: {self.detector_id}")
    
    def _generate_detector_id(self) -> str:
        """Generate unique detector ID"""
        return f"exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for exfiltration detector"""
        logger = logging.getLogger(f"ExfiltrationDetector.{self.detector_id}")
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
            fh = logging.FileHandler(f"logs/exfiltration_{self.detector_id}.log", encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"⚠️  Could not create log file: {e}")
        
        return logger
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        default_config = {
            "data_rate_threshold_kbps": 100,
            "packet_size_variance_threshold": 50,
            "timing_analysis_window": 10,
            "steganography_check": True,
            "suspicious_extensions": [".jpg", ".png", ".zip", ".rar", ".docx", ".pdf"],
            "exfiltration": {
                "volume_threshold_mb": 10,
                "unusual_hours_threshold": 0.7,
                "destination_reputation_check": True,
                "covert_channel_detection": True
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if "exfiltration_detection" in config:
                        return config["exfiltration_detection"]
                    return default_config
            else:
                print(f"[WARN] Config file not found at {config_path}, using defaults")
                return default_config
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return default_config
    
    def load_packets(self, packets, flows=None):
        """
        Load packets and optional flow data for analysis
        """
        self.packets = packets
        self.stats["total_packets"] = len(packets)
        
        # Calculate total bytes
        total_bytes = 0
        for packet in packets:
            if isinstance(packet, dict):
                length = packet.get('length', 0)
                total_bytes += length
                
                # Track bytes by destination
                dst = packet.get('dst', '0.0.0.0')
                self.stats["bytes_by_destination"][dst] += length
                
                # Track packet sizes
                self.stats["packets_by_size"][length] += 1
                
                # Track protocol
                proto = packet.get('protocol', 'Unknown')
                self.stats["flows_by_protocol"][proto] += 1
        
        self.stats["total_bytes"] = total_bytes
        
        if flows:
            self.flows = flows
            self.stats["total_flows"] = len(flows)
        
        self.logger.info(f"[LOAD] Loaded {len(packets)} packets ({total_bytes/1024/1024:.2f} MB) for exfiltration analysis")
    
    def detect_exfiltration(self):
        """
        Run all exfiltration detection methods
        """
        self.logger.info("[DETECT] Starting exfiltration detection...")
        self.stats["start_time"] = time.time()
        
        # Run all detection modules
        self._detect_volume_based_exfiltration()
        self._detect_timing_covert_channel()
        self._detect_packet_size_covert_channel()
        self._detect_unusual_protocols()
        self._detect_dns_exfiltration()
        self._detect_http_exfiltration()
        self._detect_sensitive_data_leakage()
        
        if self.steganography_check and PIL_AVAILABLE:
            self._detect_steganography()
        
        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        self.logger.info(f"[COMPLETE] Exfiltration detection completed in {duration:.2f}s")
        self.logger.info(f"           Alerts generated: {len(self.alerts)}")
        self.logger.info(f"           Exfiltration events: {len(self.exfiltration_events)}")
        
        return self.get_results()
    
    def _detect_volume_based_exfiltration(self):
        """
        Detect large data transfers to single destinations
        """
        self.logger.info("[VOLUME] Checking for large data transfers...")
        
        volume_threshold_mb = self.config.get("exfiltration", {}).get("volume_threshold_mb", 10)
        volume_threshold_bytes = volume_threshold_mb * 1024 * 1024
        
        suspicious_destinations = []
        
        for dst, bytes_sent in self.stats["bytes_by_destination"].items():
            if bytes_sent > volume_threshold_bytes:
                # Skip local/private IPs (basic check)
                if dst.startswith(('192.168.', '10.', '127.', '169.254.')):
                    continue
                
                mb_sent = bytes_sent / (1024 * 1024)
                suspicious_destinations.append({
                    "destination": dst,
                    "bytes_sent": bytes_sent,
                    "mb_sent": round(mb_sent, 2),
                    "packet_count": sum(1 for p in self.packets 
                                       if isinstance(p, dict) and p.get('dst') == dst)
                })
        
        if suspicious_destinations:
            # Sort by volume
            suspicious_destinations.sort(key=lambda x: x["bytes_sent"], reverse=True)
            
            alert = {
                "type": "large_data_transfer",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "destinations": suspicious_destinations[:5],  # Top 5
                    "total_destinations": len(suspicious_destinations),
                    "threshold_mb": volume_threshold_mb
                },
                "description": f"Detected {len(suspicious_destinations)} destinations with large data transfers (> {volume_threshold_mb}MB)"
            }
            
            self.alerts.append(alert)
            
            # Create exfiltration events
            for dst in suspicious_destinations[:3]:  # Top 3
                event = {
                    "type": "volume_exfiltration",
                    "destination": dst["destination"],
                    "data_volume_mb": dst["mb_sent"],
                    "confidence": self._calculate_confidence(dst["mb_sent"], volume_threshold_mb * 2),
                    "packets_involved": dst["packet_count"],
                    "detection_method": "volume_threshold"
                }
                self.exfiltration_events.append(event)
            
            self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_timing_covert_channel(self):
        """
        Detect timing-based covert channels
        """
        self.logger.info("[TIMING] Checking for timing-based covert channels...")
        
        # Group packets by destination
        dest_packets = defaultdict(list)
        
        for packet in self.packets:
            if isinstance(packet, dict):
                dst = packet.get('dst', '0.0.0.0')
                time_val = packet.get('time', 0)
                if time_val > 0:
                    dest_packets[dst].append({
                        "time": time_val,
                        "length": packet.get('length', 0),
                        "protocol": packet.get('protocol', 'Unknown')
                    })
        
        for dst, packets in dest_packets.items():
            if len(packets) < 10:  # Need enough packets
                continue
            
            # Sort by time
            packets.sort(key=lambda x: x["time"])
            
            # Calculate inter-arrival times
            intervals = []
            for i in range(1, len(packets)):
                interval = packets[i]["time"] - packets[i-1]["time"]
                if interval > 0:  # Skip zero intervals
                    intervals.append(interval)
            
            if len(intervals) < 5:
                continue
            
            # Analyze intervals for patterns
            if NUMPY_AVAILABLE:
                intervals_array = np.array(intervals)
                
                # Look for binary patterns (two distinct intervals)
                unique_intervals = np.unique(np.round(intervals_array, 3))
                
                if len(unique_intervals) == 2:
                    # Possible binary timing channel (0 and 1 represented by different intervals)
                    count1 = np.sum(np.isclose(intervals_array, unique_intervals[0], rtol=0.1))
                    count2 = np.sum(np.isclose(intervals_array, unique_intervals[1], rtol=0.1))
                    
                    if count1 > 3 and count2 > 3:  # Both intervals used multiple times
                        alert = {
                            "type": "timing_covert_channel",
                            "severity": "high",
                            "timestamp": time.time(),
                            "details": {
                                "destination": dst,
                                "interval1": round(unique_intervals[0], 3),
                                "interval2": round(unique_intervals[1], 3),
                                "count1": int(count1),
                                "count2": int(count2),
                                "packet_count": len(packets)
                            },
                            "description": f"Possible timing covert channel to {dst} using 2 distinct intervals"
                        }
                        self.alerts.append(alert)
                        
                        event = {
                            "type": "timing_covert_channel",
                            "destination": dst,
                            "confidence": 0.8,
                            "intervals": [round(float(unique_intervals[0]), 3), 
                                         round(float(unique_intervals[1]), 3)],
                            "detection_method": "binary_timing_pattern"
                        }
                        self.exfiltration_events.append(event)
                        
                        self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_packet_size_covert_channel(self):
        """
        Detect size-based covert channels
        """
        self.logger.info("[SIZE] Checking for size-based covert channels...")
        
        # Group packets by destination
        dest_packets = defaultdict(list)
        
        for packet in self.packets:
            if isinstance(packet, dict):
                dst = packet.get('dst', '0.0.0.0')
                length = packet.get('length', 0)
                if length > 0:
                    dest_packets[dst].append({
                        "length": length,
                        "protocol": packet.get('protocol', 'Unknown'),
                        "time": packet.get('time', 0)
                    })
        
        for dst, packets in dest_packets.items():
            if len(packets) < 10:
                continue
            
            # Extract sizes
            sizes = [p["length"] for p in packets]
            
            if NUMPY_AVAILABLE:
                sizes_array = np.array(sizes)
                unique_sizes = np.unique(sizes_array)
                
                # Look for binary pattern (2 distinct sizes)
                if len(unique_sizes) == 2:
                    count1 = np.sum(sizes_array == unique_sizes[0])
                    count2 = np.sum(sizes_array == unique_sizes[1])
                    
                    if count1 > 3 and count2 > 3:
                        # Check if sizes are significantly different
                        size_diff = abs(unique_sizes[0] - unique_sizes[1])
                        if size_diff > 50:  # Significant difference
                            alert = {
                                "type": "size_covert_channel",
                                "severity": "high",
                                "timestamp": time.time(),
                                "details": {
                                    "destination": dst,
                                    "size1": int(unique_sizes[0]),
                                    "size2": int(unique_sizes[1]),
                                    "count1": int(count1),
                                    "count2": int(count2),
                                    "size_diff": int(size_diff)
                                },
                                "description": f"Possible size-based covert channel to {dst} using 2 distinct packet sizes"
                            }
                            self.alerts.append(alert)
                            
                            event = {
                                "type": "size_covert_channel",
                                "destination": dst,
                                "confidence": 0.75,
                                "sizes": [int(unique_sizes[0]), int(unique_sizes[1])],
                                "detection_method": "binary_size_pattern"
                            }
                            self.exfiltration_events.append(event)
                            
                            self.logger.warning(f"[ALERT] {alert['description']}")
                
                # Check for many unique sizes (potential data encoding)
                elif len(unique_sizes) > len(packets) * 0.5 and len(packets) > 20:
                    alert = {
                        "type": "high_size_variance",
                        "severity": "medium",
                        "timestamp": time.time(),
                        "details": {
                            "destination": dst,
                            "unique_sizes": len(unique_sizes),
                            "total_packets": len(packets),
                            "ratio": round(len(unique_sizes) / len(packets), 2)
                        },
                        "description": f"High packet size variance to {dst} (possible data encoding)"
                    }
                    self.alerts.append(alert)
    
    def _detect_unusual_protocols(self):
        """
        Detect data exfiltration over unusual protocols
        """
        self.logger.info("[PROTO] Checking for unusual protocol usage...")
        
        # Common exfiltration protocols
        exfil_protocols = {
            "ICMP": {"suspicious": True, "reason": "Can tunnel data in echo requests"},
            "DNS": {"suspicious": True, "reason": "Common for tunneling"},
            "NTP": {"suspicious": True, "reason": "Can hide data in timestamps"},
            "DHCP": {"suspicious": True, "reason": "Options field can carry data"},
            "ARP": {"suspicious": True, "reason": "No legitimate large data transfer"}
        }
        
        # Group by destination and protocol
        dest_proto_volume = defaultdict(lambda: defaultdict(int))
        
        for packet in self.packets:
            if isinstance(packet, dict):
                dst = packet.get('dst', '0.0.0.0')
                proto = packet.get('protocol', 'Unknown')
                length = packet.get('length', 0)
                
                dest_proto_volume[dst][proto] += length
        
        for dst, protocols in dest_proto_volume.items():
            for proto, bytes_vol in protocols.items():
                if proto in exfil_protocols and bytes_vol > 10000:  # >10KB over unusual protocol
                    mb_vol = bytes_vol / (1024 * 1024)
                    alert = {
                        "type": "unusual_protocol_exfiltration",
                        "severity": "high",
                        "timestamp": time.time(),
                        "details": {
                            "destination": dst,
                            "protocol": proto,
                            "bytes": bytes_vol,
                            "mb": round(mb_vol, 2),
                            "reason": exfil_protocols[proto]["reason"]
                        },
                        "description": f"Large data transfer ({mb_vol:.2f}MB) over {proto} to {dst} - {exfil_protocols[proto]['reason']}"
                    }
                    self.alerts.append(alert)
                    
                    event = {
                        "type": "protocol_exfiltration",
                        "destination": dst,
                        "protocol": proto,
                        "data_volume_mb": round(mb_vol, 2),
                        "confidence": 0.85,
                        "detection_method": "unusual_protocol_volume"
                    }
                    self.exfiltration_events.append(event)
                    
                    self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_dns_exfiltration(self):
        """
        Detect DNS-based exfiltration
        """
        self.logger.info("[DNS] Checking for DNS exfiltration...")
        
        dns_queries = []
        
        for packet in self.packets:
            if isinstance(packet, dict):
                proto = packet.get('protocol', '')
                info = packet.get('info', '')
                
                if proto == "DNS" or "DNS" in info:
                    # Extract query
                    query = ""
                    if "Query:" in info:
                        query = info.split("Query:")[-1].strip()
                    elif "DNS" in info:
                        query = info
                    
                    if query:
                        dns_queries.append({
                            "query": query,
                            "length": len(query),
                            "time": packet.get('time', 0),
                            "dst": packet.get('dst', ''),
                            "raw_data": packet.get('raw_data', b'')
                        })
        
        if len(dns_queries) < 5:
            return
        
        # Analyze DNS query patterns
        suspicious_queries = []
        
        for query in dns_queries:
            query_str = query["query"]
            
            # Check for long queries
            if query["length"] > 50:
                # Calculate entropy
                if isinstance(query["raw_data"], bytes) and len(query["raw_data"]) > 0:
                    entropy = self._calculate_entropy(query["raw_data"])
                else:
                    entropy = self._calculate_entropy(query_str.encode())
                
                suspicious_queries.append({
                    **query,
                    "entropy": round(entropy, 3),
                    "reason": "long_query"
                })
            
            # Check for subdomain encoding
            parts = query_str.split('.')
            if len(parts) > 5:  # Many subdomains
                suspicious_queries.append({
                    **query,
                    "subdomain_count": len(parts),
                    "reason": "many_subdomains"
                })
            
            # Check for base64-like patterns
            base64_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=')
            domain_part = parts[0] if parts else ""
            if domain_part and all(c in base64_chars for c in domain_part[:20]):
                suspicious_queries.append({
                    **query,
                    "reason": "base64_pattern"
                })
        
        if suspicious_queries:
            # Group by destination
            dest_queries = defaultdict(list)
            for q in suspicious_queries:
                dest_queries[q["dst"]].append(q)
            
            for dst, queries in dest_queries.items():
                alert = {
                    "type": "dns_exfiltration",
                    "severity": "high",
                    "timestamp": time.time(),
                    "details": {
                        "destination": dst,
                        "suspicious_queries": len(queries),
                        "total_dns_queries": len(dns_queries),
                        "samples": queries[:3]  # First 3 samples
                    },
                    "description": f"Possible DNS exfiltration to {dst} - {len(queries)} suspicious queries detected"
                }
                self.alerts.append(alert)
                
                event = {
                    "type": "dns_exfiltration",
                    "destination": dst,
                    "confidence": 0.9,
                    "query_count": len(queries),
                    "detection_method": "dns_tunneling_patterns"
                }
                self.exfiltration_events.append(event)
                
                self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_http_exfiltration(self):
        """
        Detect HTTP-based exfiltration
        """
        self.logger.info("[HTTP] Checking for HTTP exfiltration...")
        
        http_requests = []
        
        for packet in self.packets:
            if isinstance(packet, dict):
                proto = packet.get('protocol', '')
                info = packet.get('info', '')
                dport = packet.get('dport', 0)
                
                # Check for HTTP traffic
                if proto == "HTTP" or dport == 80 or dport == 8080 or info.startswith(('GET ', 'POST ')):
                    # Extract request details
                    method = ""
                    uri = ""
                    if info:
                        parts = info.split(' ')
                        if len(parts) > 1:
                            method = parts[0]
                            uri = parts[1] if len(parts) > 1 else ""
                    
                    http_requests.append({
                        "method": method,
                        "uri": uri,
                        "length": len(uri),
                        "time": packet.get('time', 0),
                        "dst": packet.get('dst', ''),
                        "raw_data": packet.get('raw_data', b'')
                    })
        
        if len(http_requests) < 3:
            return
        
        # Check for suspicious patterns
        suspicious_requests = []
        
        for req in http_requests:
            # Long URIs (potential data encoding)
            if req["length"] > 200:
                suspicious_requests.append({
                    **req,
                    "reason": "long_uri"
                })
            
            # POST with large body
            if req["method"] == "POST" and req["raw_data"] and len(req["raw_data"]) > 1000:
                suspicious_requests.append({
                    **req,
                    "reason": "large_post",
                    "data_size": len(req["raw_data"])
                })
            
            # Unusual User-Agent would require header parsing (future enhancement)
        
        if suspicious_requests:
            # Group by destination
            dest_requests = defaultdict(list)
            for req in suspicious_requests:
                dest_requests[req["dst"]].append(req)
            
            for dst, requests in dest_requests.items():
                alert = {
                    "type": "http_exfiltration",
                    "severity": "medium",
                    "timestamp": time.time(),
                    "details": {
                        "destination": dst,
                        "suspicious_requests": len(requests),
                        "total_http_requests": len(http_requests),
                        "samples": requests[:3]
                    },
                    "description": f"Possible HTTP exfiltration to {dst} - {len(requests)} suspicious requests"
                }
                self.alerts.append(alert)
                
                event = {
                    "type": "http_exfiltration",
                    "destination": dst,
                    "confidence": 0.7,
                    "request_count": len(requests),
                    "detection_method": "long_uri_large_post"
                }
                self.exfiltration_events.append(event)
                
                self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_sensitive_data_leakage(self):
        """
        Detect sensitive data patterns in outgoing traffic
        """
        self.logger.info("[LEAK] Checking for sensitive data leakage...")
        
        leak_events = []
        
        for i, packet in enumerate(self.packets):
            if isinstance(packet, dict):
                # Skip incoming packets? (simplified - check if dest is external)
                dst = packet.get('dst', '')
                if dst.startswith(('192.168.', '10.', '127.')):
                    continue
                
                raw_data = packet.get('raw_data', b'')
                if isinstance(raw_data, str):
                    raw_data = raw_data.encode('utf-8', errors='ignore')
                
                if not raw_data or len(raw_data) < 10:
                    continue
                
                # Check for sensitive patterns
                for pattern in self.sensitive_patterns:
                    if pattern.lower() in raw_data.lower():
                        # Find context (surrounding bytes)
                        pos = raw_data.lower().find(pattern.lower())
                        start = max(0, pos - 20)
                        end = min(len(raw_data), pos + len(pattern) + 20)
                        context = raw_data[start:end]
                        
                        leak_events.append({
                            "packet_index": i,
                            "pattern": pattern.decode('utf-8', errors='ignore'),
                            "context": context.decode('utf-8', errors='ignore').replace('\n', ' '),
                            "destination": dst,
                            "timestamp": packet.get('time', 0)
                        })
                        break  # One pattern per packet
        
        if leak_events:
            alert = {
                "type": "sensitive_data_leakage",
                "severity": "critical",
                "timestamp": time.time(),
                "details": {
                    "leak_count": len(leak_events),
                    "samples": leak_events[:5]  # First 5 samples
                },
                "description": f"Detected {len(leak_events)} instances of sensitive data leakage"
            }
            self.alerts.append(alert)
            
            event = {
                "type": "data_leakage",
                "confidence": 0.95,
                "instance_count": len(leak_events),
                "patterns_found": list(set(e["pattern"] for e in leak_events)),
                "detection_method": "pattern_matching"
            }
            self.exfiltration_events.append(event)
            
            self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_steganography(self):
        """
        Detect steganography in image files transferred over network
        """
        self.logger.info("[STEGO] Checking for steganography in image transfers...")
        
        if not PIL_AVAILABLE:
            self.logger.info("[STEGO] PIL not available - skipping steganography detection")
            return
        
        # Look for image file transfers
        image_transfers = []
        
        for packet in self.packets:
            if isinstance(packet, dict):
                info = packet.get('info', '')
                raw_data = packet.get('raw_data', b'')
                
                # Check for image file extensions in HTTP
                for ext in self.suspicious_extensions:
                    if ext in info.lower() and ('.jpg' in info.lower() or '.png' in info.lower()):
                        image_transfers.append({
                            "packet": packet,
                            "extension": ext,
                            "info": info,
                            "raw_data": raw_data
                        })
                        break
        
        if not image_transfers:
            return
        
        # In a real implementation, you would:
        # 1. Reconstruct the full image from multiple packets
        # 2. Save it to a temporary file
        # 3. Analyze for steganography (LSB analysis, etc.)
        
        # For now, we'll flag potential steganography carriers
        alert = {
            "type": "potential_steganography_carrier",
            "severity": "medium",
            "timestamp": time.time(),
            "details": {
                "image_transfers": len(image_transfers),
                "extensions": list(set(t["extension"] for t in image_transfers)),
                "samples": [{"info": t["info"][:50]} for t in image_transfers[:3]]
            },
            "description": f"Detected {len(image_transfers)} image transfers that could contain steganography"
        }
        self.alerts.append(alert)
        
        self.logger.info(f"[STEGO] {alert['description']}")
    
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
    
    def _calculate_confidence(self, value, threshold):
        """
        Calculate confidence score based on value relative to threshold
        """
        if value >= threshold * 2:
            return 0.95
        elif value >= threshold * 1.5:
            return 0.85
        elif value >= threshold:
            return 0.75
        else:
            return 0.5
    
    def get_results(self):
        """
        Get complete detection results
        """
        return {
            "detector_id": self.detector_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "total_packets": self.stats["total_packets"],
                "total_bytes": self.stats["total_bytes"],
                "total_mb": round(self.stats["total_bytes"] / (1024 * 1024), 2),
                "total_flows": self.stats["total_flows"],
                "unique_destinations": len(self.stats["bytes_by_destination"]),
                "top_destinations": sorted(
                    [{"ip": k, "mb": round(v/(1024*1024), 2)} 
                     for k, v in self.stats["bytes_by_destination"].items()],
                    key=lambda x: x["mb"],
                    reverse=True
                )[:5]
            },
            "alerts": self.alerts,
            "exfiltration_events": self.exfiltration_events,
            "summary": {
                "total_alerts": len(self.alerts),
                "total_events": len(self.exfiltration_events),
                "by_severity": {
                    "critical": sum(1 for a in self.alerts if a["severity"] == "critical"),
                    "high": sum(1 for a in self.alerts if a["severity"] == "high"),
                    "medium": sum(1 for a in self.alerts if a["severity"] == "medium"),
                    "low": sum(1 for a in self.alerts if a["severity"] == "low")
                }
            }
        }
    
    def generate_report(self, format="json"):
        """
        Generate exfiltration detection report
        """
        results = self.get_results()
        
        if format == "json":
            report_file = f"output/exfiltration/exfil_{self.detector_id}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"[REPORT] JSON report saved to: {report_file}")
            return report_file
        
        elif format == "text":
            # Generate text summary
            lines = []
            lines.append("=" * 60)
            lines.append(f"EXFILTRATION DETECTION REPORT - {self.detector_id}")
            lines.append("=" * 60)
            lines.append("")
            
            # Statistics
            lines.append("📊 STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Total Packets: {results['statistics']['total_packets']}")
            lines.append(f"Total Data: {results['statistics']['total_mb']} MB")
            lines.append(f"Unique Destinations: {results['statistics']['unique_destinations']}")
            lines.append("")
            
            # Top destinations
            lines.append("🎯 TOP DESTINATIONS BY VOLUME")
            lines.append("-" * 40)
            for dest in results['statistics']['top_destinations']:
                lines.append(f"  {dest['ip']}: {dest['mb']} MB")
            lines.append("")
            
            # Exfiltration events
            lines.append("🚨 EXFILTRATION EVENTS")
            lines.append("-" * 40)
            if results['exfiltration_events']:
                for event in results['exfiltration_events']:
                    confidence_bar = "█" * int(event['confidence'] * 10) + "░" * (10 - int(event['confidence'] * 10))
                    lines.append(f"  [{event['type']}] Confidence: {event['confidence']:.0%} {confidence_bar}")
                    if 'destination' in event:
                        lines.append(f"     Destination: {event['destination']}")
                    if 'data_volume_mb' in event:
                        lines.append(f"     Volume: {event['data_volume_mb']} MB")
                    lines.append("")
            else:
                lines.append("  No exfiltration events detected")
            lines.append("")
            
            # Alerts
            lines.append("⚠️  ALERTS")
            lines.append("-" * 40)
            if results['alerts']:
                for alert in results['alerts']:
                    severity_symbol = {
                        "critical": "🔥",
                        "high": "🔴",
                        "medium": "🟡",
                        "low": "🟢"
                    }.get(alert["severity"], "⚪")
                    lines.append(f"  {severity_symbol} [{alert['severity'].upper()}] {alert['type']}")
                    lines.append(f"     {alert['description']}")
                    lines.append("")
            else:
                lines.append("  No alerts generated")
            lines.append("")
            
            lines.append("=" * 60)
            
            report_text = "\n".join(lines)
            
            # Save to file
            report_file = f"output/exfiltration/exfil_{self.detector_id}.txt"
            with open(report_file, 'w') as f:
                f.write(report_text)
            
            self.logger.info(f"[REPORT] Text report saved to: {report_file}")
            return report_file
        
        return results
    
    def cleanup(self):
        """
        Clean up detector resources
        """
        self.packets = []
        self.alerts = []
        self.exfiltration