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

# Try to import PIL for image analysis
try:
    from PIL import Image
    from PIL import ImageStat
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Try to import magic for file type detection
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

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
        self.detection_id = self._generate_detection_id()
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Detection results
        self.packets = []
        self.alerts = []
        self.suspicious_flows = {}
        self.exfil_attempts = []
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "total_flows": 0,
            "start_time": None,
            "end_time": None,
            "outbound_bytes": 0,
            "inbound_bytes": 0,
            "unique_destinations": set()
        }
        
        # Detection thresholds from config
        self.data_rate_threshold = self.config.get("data_rate_threshold_kbps", 100)  # KB/s
        self.packet_size_variance_threshold = self.config.get("packet_size_variance_threshold", 50)
        self.timing_window = self.config.get("timing_analysis_window", 10)
        self.steganography_check = self.config.get("steganography_check", True)
        self.suspicious_extensions = self.config.get("suspicious_extensions", 
                                                    [".jpg", ".png", ".zip", ".rar", ".docx", ".pdf"])
        
        # Internal tracking
        self.flow_bytes = defaultdict(int)
        self.flow_packets = defaultdict(list)
        self.flow_timestamps = defaultdict(list)
        self.destination_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": set()})
        
        # Create output directory
        os.makedirs("output/exfiltration", exist_ok=True)
        
        self.logger.info(f"[TOOL] ExfiltrationDetector initialized with ID: {self.detection_id}")
    
    def _generate_detection_id(self) -> str:
        """Generate unique detection ID"""
        return f"exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for exfiltration detector"""
        logger = logging.getLogger(f"ExfiltrationDetector.{self.detection_id}")
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
            fh = logging.FileHandler(f"logs/exfiltration_{self.detection_id}.log", encoding='utf-8')
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
                "outbound_threshold_mb": 10,
                "suspicious_countries": [],
                "unusual_ports": [21, 22, 53, 123, 443, 8080],
                "covert_channel_detection": True,
                "dns_exfiltration_detection": True,
                "icmp_exfiltration_detection": True,
                "http_exfiltration_detection": True
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
    
    def load_packets(self, packets):
        """
        Load packets for exfiltration analysis
        """
        self.packets = packets
        self.stats["total_packets"] = len(packets)
        self.logger.info(f"[LOAD] Loaded {len(packets)} packets for exfiltration analysis")
        
        # Calculate total bytes and classify traffic
        total_bytes = 0
        outbound_bytes = 0
        inbound_bytes = 0
        
        for packet in packets:
            if isinstance(packet, dict):
                length = packet.get('length', 0)
                total_bytes += length
                
                # Simple classification (assuming internal IP is 192.168.x.x or 10.x.x.x)
                src = packet.get('src', '0.0.0.0')
                if src.startswith(('192.168.', '10.', '172.16.')):
                    outbound_bytes += length
                    self.stats["outbound_bytes"] += length
                else:
                    inbound_bytes += length
                    self.stats["inbound_bytes"] += length
                
                # Track unique destinations
                dst = packet.get('dst', '0.0.0.0')
                if dst and dst != '0.0.0.0':
                    self.stats["unique_destinations"].add(dst)
        
        self.stats["total_bytes"] = total_bytes
    
    def detect_exfiltration(self):
        """
        Run all exfiltration detection methods
        """
        self.logger.info("[DETECT] Starting exfiltration detection...")
        self.stats["start_time"] = time.time()
        
        if not self.packets:
            self.logger.warning("[WARN] No packets to analyze")
            return {}
        
        # Build flow statistics first
        self._build_flow_statistics()
        
        # Run all detection modules
        self._detect_large_transfers()
        self._detect_unusual_destinations()
        self._detect_data_rate_anomalies()
        self._detect_dns_exfiltration()
        self._detect_icmp_exfiltration()
        self._detect_http_exfiltration()
        self._detect_covert_channels()
        self._detect_timing_channels()
        self._detect_steganography()
        self._detect_unusual_protocols()
        self._detect_packet_size_anomalies()
        
        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        self.logger.info(f"[COMPLETE] Exfiltration detection completed in {duration:.2f}s")
        self.logger.info(f"           Alerts generated: {len(self.alerts)}")
        self.logger.info(f"           Suspicious flows: {len(self.suspicious_flows)}")
        
        return self.get_results()
    
    def _build_flow_statistics(self):
        """
        Build flow-based statistics for analysis
        """
        self.logger.info("[FLOWS] Building flow statistics...")
        
        for i, packet in enumerate(self.packets):
            if not isinstance(packet, dict):
                continue
            
            # Extract flow key
            src = packet.get('src', '0.0.0.0')
            dst = packet.get('dst', '0.0.0.0')
            sport = packet.get('sport', 0)
            dport = packet.get('dport', 0)
            proto = packet.get('protocol', 'Unknown')
            length = packet.get('length', 0)
            time_val = packet.get('time', time.time())
            
            # Create flow key (outbound direction)
            if src.startswith(('192.168.', '10.', '172.16.')):
                flow_key = f"{proto}_{src}:{sport}->{dst}:{dport}"
            else:
                flow_key = f"{proto}_{dst}:{dport}->{src}:{sport}"  # Inbound
            
            # Update flow statistics
            self.flow_bytes[flow_key] += length
            self.flow_packets[flow_key].append({
                "index": i,
                "length": length,
                "time": time_val
            })
            self.flow_timestamps[flow_key].append(time_val)
            
            # Update destination statistics
            self.destination_stats[dst]["bytes"] += length
            self.destination_stats[dst]["packets"] += 1
            self.destination_stats[dst]["flows"].add(flow_key)
        
        self.stats["total_flows"] = len(self.flow_bytes)
    
    def _detect_large_transfers(self):
        """
        Detect unusually large data transfers
        """
        self.logger.info("[TRANSFER] Checking for large data transfers...")
        
        threshold_mb = self.config.get("exfiltration", {}).get("outbound_threshold_mb", 10)
        threshold_bytes = threshold_mb * 1024 * 1024
        
        large_transfers = []
        
        for flow_key, bytes_sent in self.flow_bytes.items():
            if bytes_sent > threshold_bytes:
                # Extract destination info
                parts = flow_key.split('->')
                if len(parts) > 1:
                    dest_info = parts[1]
                    dest_ip = dest_info.split(':')[0]
                else:
                    dest_ip = "unknown"
                
                large_transfers.append({
                    "flow": flow_key,
                    "bytes": bytes_sent,
                    "megabytes": round(bytes_sent / (1024 * 1024), 2),
                    "destination": dest_ip,
                    "packet_count": len(self.flow_packets[flow_key])
                })
                
                # Mark flow as suspicious
                self.suspicious_flows[flow_key] = {
                    "reason": "large_transfer",
                    "bytes": bytes_sent,
                    "severity": "high"
                }
        
        if large_transfers:
            alert = {
                "type": "large_data_transfer",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "transfers": large_transfers[:5],  # Top 5
                    "total_large_transfers": len(large_transfers),
                    "threshold_mb": threshold_mb
                },
                "description": f"Detected {len(large_transfers)} large data transfers exceeding {threshold_mb}MB"
            }
            self.alerts.append(alert)
            self.logger.warning(f"[ALERT] {alert['description']}")
    
    def _detect_unusual_destinations(self):
        """
        Detect connections to unusual or suspicious destinations
        """
        self.logger.info("[DEST] Checking for unusual destinations...")
        
        # Known suspicious IP ranges (can be expanded)
        suspicious_ranges = [
            "45.", "46.",  # Eastern Europe
            "5.",          # Middle East
            "185.", "188.", "193.", "194.", "195."  # Various
        ]
        
        # Known bad ASNs/countries from config
        suspicious_countries = self.config.get("exfiltration", {}).get("suspicious_countries", [])
        
        unusual_destinations = []
        
        for dst_ip, stats in self.destination_stats.items():
            if dst_ip == '0.0.0.0' or dst_ip.startswith(('192.168.', '10.', '172.16.', '127.')):
                continue  # Skip internal/local
            
            # Check against suspicious ranges
            for suspicious in suspicious_ranges:
                if dst_ip.startswith(suspicious):
                    unusual_destinations.append({
                        "destination": dst_ip,
                        "bytes": stats["bytes"],
                        "megabytes": round(stats["bytes"] / (1024 * 1024), 2),
                        "packets": stats["packets"],
                        "flows": len(stats["flows"]),
                        "reason": "suspicious_ip_range"
                    })
                    break
        
        if unusual_destinations:
            alert = {
                "type": "unusual_destination",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "destinations": unusual_destinations[:5],
                    "total_unusual": len(unusual_destinations)
                },
                "description": f"Detected connections to {len(unusual_destinations)} unusual IP addresses"
            }
            self.alerts.append(alert)
    
    def _detect_data_rate_anomalies(self):
        """
        Detect anomalies in data transfer rates
        """
        self.logger.info("[RATE] Analyzing data transfer rates...")
        
        if len(self.packets) < 10:
            return
        
        # Group packets by time windows
        window_seconds = 5
        time_windows = defaultdict(lambda: {"bytes": 0, "packets": 0})
        
        for packet in self.packets:
            if not isinstance(packet, dict):
                continue
            
            time_val = packet.get('time', 0)
            length = packet.get('length', 0)
            src = packet.get('src', '0.0.0.0')
            
            # Only count outbound
            if src.startswith(('192.168.', '10.', '172.16.')):
                window_key = int(time_val / window_seconds)
                time_windows[window_key]["bytes"] += length
                time_windows[window_key]["packets"] += 1
        
        if not time_windows:
            return
        
        # Calculate rates
        rates = []
        for window, data in sorted(time_windows.items()):
            rate_kbps = (data["bytes"] * 8) / (window_seconds * 1000)  # kbps
            rates.append(rate_kbps)
        
        # Find spikes
        if NUMPY_AVAILABLE and len(rates) > 3:
            rates_array = np.array(rates)
            mean_rate = np.mean(rates_array)
            std_rate = np.std(rates_array)
            
            spikes = []
            for i, rate in enumerate(rates):
                if rate > mean_rate + 3 * std_rate:  # Statistical outlier
                    spikes.append({
                        "window": i,
                        "rate_kbps": round(rate, 2),
                        "bytes": time_windows[i]["bytes"],
                        "packets": time_windows[i]["packets"]
                    })
            
            if spikes:
                alert = {
                    "type": "data_rate_spike",
                    "severity": "medium",
                    "timestamp": time.time(),
                    "details": {
                        "spikes": spikes,
                        "mean_rate_kbps": round(mean_rate, 2),
                        "threshold_kbps": round(mean_rate + 3 * std_rate, 2)
                    },
                    "description": f"Detected {len(spikes)} data rate spikes (possible exfiltration burst)"
                }
                self.alerts.append(alert)
    
    def _detect_dns_exfiltration(self):
        """
        Detect data exfiltration over DNS
        """
        self.logger.info("[DNS] Checking for DNS exfiltration...")
        
        dns_flows = []
        
        # Find DNS flows
        for flow_key, packets in self.flow_packets.items():
            if "DNS" in flow_key or ":53" in flow_key:
                dns_flows.append((flow_key, packets))
        
        if not dns_flows:
            return
        
        suspicious_dns = []
        
        for flow_key, packets in dns_flows:
            # Check for high packet count (many DNS queries)
            if len(packets) > 50:
                suspicious_dns.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "total_bytes": self.flow_bytes[flow_key],
                    "reason": "high_query_volume"
                })
                continue
            
            # Check for large DNS packets
            large_packets = [p for p in packets if p["length"] > 512]  # Max normal DNS size
            if large_packets:
                suspicious_dns.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "large_packets": len(large_packets),
                    "total_bytes": self.flow_bytes[flow_key],
                    "reason": "large_dns_packets"
                })
                continue
            
            # Check for consistent packet sizes (potential encoding)
            if len(packets) > 10:
                sizes = [p["length"] for p in packets]
                if NUMPY_AVAILABLE:
                    std_size = np.std(sizes)
                    if std_size < 10:  # Very consistent sizes
                        suspicious_dns.append({
                            "flow": flow_key,
                            "packet_count": len(packets),
                            "std_size": round(std_size, 2),
                            "reason": "consistent_packet_sizes"
                        })
        
        if suspicious_dns:
            alert = {
                "type": "dns_exfiltration",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "suspicious_flows": suspicious_dns[:5],
                    "total_suspicious": len(suspicious_dns)
                },
                "description": f"Detected {len(suspicious_dns)} suspicious DNS flows (possible exfiltration)"
            }
            self.alerts.append(alert)
            
            # Mark flows as suspicious
            for sus in suspicious_dns:
                self.suspicious_flows[sus["flow"]] = {
                    "reason": f"dns_exfiltration_{sus['reason']}",
                    "severity": "high"
                }
    
    def _detect_icmp_exfiltration(self):
        """
        Detect data exfiltration over ICMP (ping tunneling)
        """
        self.logger.info("[ICMP] Checking for ICMP exfiltration...")
        
        icmp_flows = []
        
        # Find ICMP flows
        for flow_key, packets in self.flow_packets.items():
            if "ICMP" in flow_key:
                icmp_flows.append((flow_key, packets))
        
        if not icmp_flows:
            return
        
        suspicious_icmp = []
        
        for flow_key, packets in icmp_flows:
            # ICMP should normally have small packets
            large_packets = [p for p in packets if p["length"] > 100]
            
            if large_packets:
                suspicious_icmp.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "large_packets": len(large_packets),
                    "total_bytes": self.flow_bytes[flow_key],
                    "reason": "large_icmp_packets"
                })
                continue
            
            # Check for high volume
            if len(packets) > 100:
                suspicious_icmp.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "total_bytes": self.flow_bytes[flow_key],
                    "reason": "high_icmp_volume"
                })
        
        if suspicious_icmp:
            alert = {
                "type": "icmp_exfiltration",
                "severity": "high",
                "timestamp": time.time(),
                "details": {
                    "suspicious_flows": suspicious_icmp[:5],
                    "total_suspicious": len(suspicious_icmp)
                },
                "description": f"Detected {len(suspicious_icmp)} suspicious ICMP flows (possible ping tunneling)"
            }
            self.alerts.append(alert)
    
    def _detect_http_exfiltration(self):
        """
        Detect data exfiltration over HTTP
        """
        self.logger.info("[HTTP] Checking for HTTP exfiltration...")
        
        http_flows = []
        
        # Find HTTP flows (port 80 or protocol HTTP)
        for flow_key, packets in self.flow_packets.items():
            if "HTTP" in flow_key or ":80" in flow_key or ":8080" in flow_key:
                http_flows.append((flow_key, packets))
        
        if not http_flows:
            return
        
        suspicious_http = []
        
        for flow_key, packets in http_flows:
            # Check for large outbound POST requests
            total_bytes = self.flow_bytes[flow_key]
            
            if total_bytes > 1024 * 1024:  # > 1MB
                suspicious_http.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                    "reason": "large_http_upload"
                })
                continue
            
            # Check for many small requests (beaconing)
            if len(packets) > 50 and total_bytes < 100 * 1024:  # Many small packets
                suspicious_http.append({
                    "flow": flow_key,
                    "packet_count": len(packets),
                    "total_bytes": total_bytes,
                    "reason": "http_beaconing"
                })
        
        if suspicious_http:
            alert = {
                "type": "http_exfiltration",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "suspicious_flows": suspicious_http[:5],
                    "total_suspicious": len(suspicious_http)
                },
                "description": f"Detected {len(suspicious_http)} suspicious HTTP flows"
            }
            self.alerts.append(alert)
    
    def _detect_covert_channels(self):
        """
        Detect various covert channel techniques
        """
        self.logger.info("[COVERT] Checking for covert channels...")
        
        for flow_key, packets in self.flow_packets.items():
            if len(packets) < 10:
                continue
            
            # Check 1: Fixed packet sizes (potential encoding)
            sizes = [p["length"] for p in packets]
            unique_sizes = set(sizes)
            
            if len(unique_sizes) == 1 and len(packets) > 20:
                # All packets exactly the same size
                alert = {
                    "type": "covert_channel_fixed_size",
                    "severity": "high",
                    "timestamp": time.time(),
                    "details": {
                        "flow": flow_key,
                        "packet_count": len(packets),
                        "packet_size": sizes[0],
                        "total_bytes": self.flow_bytes[flow_key]
                    },
                    "description": f"Covert channel detected: all {len(packets)} packets identical size ({sizes[0]} bytes)"
                }
                self.alerts.append(alert)
                self.suspicious_flows[flow_key] = {"reason": "covert_fixed_size", "severity": "high"}
                continue
            
            # Check 2: Alternating packet sizes (binary encoding)
            if len(packets) > 20 and len(unique_sizes) == 2:
                # Check if sizes alternate (0/1 encoding)
                size_pattern = [sizes[i] for i in range(min(20, len(sizes)))]
                # Simple check for alternating pattern
                alternating = all(size_pattern[i] != size_pattern[i+1] for i in range(len(size_pattern)-1))
                
                if alternating:
                    alert = {
                        "type": "covert_channel_alternating",
                        "severity": "high",
                        "timestamp": time.time(),
                        "details": {
                            "flow": flow_key,
                            "packet_count": len(packets),
                            "size1": list(unique_sizes)[0],
                            "size2": list(unique_sizes)[1],
                            "pattern": size_pattern[:10]
                        },
                        "description": f"Covert channel detected: alternating packet sizes (possible binary encoding)"
                    }
                    self.alerts.append(alert)
                    self.suspicious_flows[flow_key] = {"reason": "covert_alternating", "severity": "high"}
    
    def _detect_timing_channels(self):
        """
        Detect timing-based covert channels
        """
        self.logger.info("[TIMING] Checking for timing channels...")
        
        for flow_key, timestamps in self.flow_timestamps.items():
            if len(timestamps) < 10:
                continue
            
            # Calculate inter-arrival times
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            if not intervals:
                continue
            
            # Check for repeating interval patterns
            if NUMPY_AVAILABLE:
                intervals_array = np.array(intervals)
                
                # Look for very low variance (regular heartbeat)
                if np.std(intervals_array) < 0.01 and np.mean(intervals_array) > 0:
                    alert = {
                        "type": "timing_channel_regular",
                        "severity": "high",
                        "timestamp": time.time(),
                        "details": {
                            "flow": flow_key,
                            "mean_interval": round(np.mean(intervals_array), 4),
                            "std_interval": round(np.std(intervals_array), 4),
                            "packet_count": len(timestamps)
                        },
                        "description": f"Timing channel detected: extremely regular intervals ({np.mean(intervals_array):.4f}s ± {np.std(intervals_array):.4f}s)"
                    }
                    self.alerts.append(alert)
                    self.suspicious_flows[flow_key] = {"reason": "timing_channel", "severity": "high"}
                    continue
            
            # Simple check for identical intervals
            if len(intervals) > 5:
                rounded_intervals = [round(i, 3) for i in intervals]
                if len(set(rounded_intervals)) == 1:
                    alert = {
                        "type": "timing_channel_identical",
                        "severity": "high",
                        "timestamp": time.time(),
                        "details": {
                            "flow": flow_key,
                            "interval": intervals[0],
                            "packet_count": len(timestamps)
                        },
                        "description": f"Timing channel detected: all packet intervals identical ({intervals[0]:.4f}s)"
                    }
                    self.alerts.append(alert)
    
    def _detect_steganography(self):
        """
        Detect possible steganography in transferred files
        """
        if not self.steganography_check:
            return
        
        self.logger.info("[STEGO] Checking for steganography...")
        
        if not PIL_AVAILABLE:
            self.logger.info("[STEGO] PIL not available, skipping image analysis")
            return
        
        # Look for image file transfers
        image_transfers = []
        
        for flow_key, packets in self.flow_packets.items():
            # Check if this flow might contain images
            total_bytes = self.flow_bytes[flow_key]
            
            # Images are typically > 10KB
            if total_bytes > 10 * 1024:
                # Check packet patterns that might indicate image transfer
                # This is a simplified detection - real stego detection would need file extraction
                
                # Look for consistent large packets (typical for file transfer)
                large_packets = [p for p in packets if p["length"] > 1000]
                if len(large_packets) > 5:
                    image_transfers.append({
                        "flow": flow_key,
                        "total_kb": round(total_bytes / 1024, 2),
                        "large_packets": len(large_packets),
                        "total_packets": len(packets)
                    })
        
        if image_transfers:
            alert = {
                "type": "possible_steganography",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "suspicious_transfers": image_transfers[:5],
                    "note": "Image files detected - further analysis recommended"
                },
                "description": f"Detected {len(image_transfers)} potential image transfers (possible steganography)"
            }
            self.alerts.append(alert)
    
    def _detect_unusual_protocols(self):
        """
        Detect data exfiltration over unusual protocols/ports
        """
        self.logger.info("[PROTO] Checking for unusual protocols...")
        
        unusual_ports = self.config.get("exfiltration", {}).get("unusual_ports", 
                                                               [21, 22, 53, 123, 443, 8080])
        
        unusual_flows = []
        
        for flow_key, bytes_sent in self.flow_bytes.items():
            # Extract port information
            parts = flow_key.split('->')
            if len(parts) < 2:
                continue
            
            dest_part = parts[1]
            if ':' in dest_part:
                port = int(dest_part.split(':')[1])
                
                # Check if port is in unusual list
                if port in unusual_ports and bytes_sent > 1024 * 1024:  # > 1MB on unusual port
                    unusual_flows.append({
                        "flow": flow_key,
                        "port": port,
                        "bytes": bytes_sent,
                        "megabytes": round(bytes_sent / (1024 * 1024), 2)
                    })
        
        if unusual_flows:
            alert = {
                "type": "unusual_protocol_exfiltration",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "flows": unusual_flows[:5],
                    "total_unusual": len(unusual_flows)
                },
                "description": f"Detected {len(unusual_flows)} large transfers over unusual ports"
            }
            self.alerts.append(alert)
    
    def _detect_packet_size_anomalies(self):
        """
        Detect anomalies in packet sizes that might indicate exfiltration
        """
        self.logger.info("[SIZE] Analyzing packet size patterns...")
        
        # Group packets by size
        size_distribution = Counter()
        for packet in self.packets:
            if isinstance(packet, dict):
                size_distribution[packet.get('length', 0)] += 1
        
        if not size_distribution:
            return
        
        # Look for unusual size clusters
        total_packets = sum(size_distribution.values())
        
        # MTU-sized packets (maximum size) could be exfiltration
        mtu_sizes = [size for size in size_distribution if 1400 <= size <= 1500]
        mtu_packets = sum(size_distribution[size] for size in mtu_sizes)
        
        if mtu_packets > total_packets * 0.5 and mtu_packets > 100:
            alert = {
                "type": "mtu_sized_packets",
                "severity": "medium",
                "timestamp": time.time(),
                "details": {
                    "mtu_packets": mtu_packets,
                    "percentage": round(mtu_packets / total_packets * 100, 2),
                    "total_packets": total_packets
                },
                "description": f"High percentage ({mtu_packets/total_packets*100:.1f}%) of MTU-sized packets (possible data exfiltration)"
            }
            self.alerts.append(alert)
        
        # Look for very small packets with high frequency (potential signaling)
        small_packets = [size for size in size_distribution if size < 100]
        small_count = sum(size_distribution[size] for size in small_packets)
        
        if small_count > total_packets * 0.3 and small_count > 50:
            alert = {
                "type": "many_small_packets",
                "severity": "low",
                "timestamp": time.time(),
                "details": {
                    "small_packets": small_count,
                    "percentage": round(small_count / total_packets * 100, 2)
                },
                "description": f"High percentage of very small packets (possible covert signaling)"
            }
            self.alerts.append(alert)
    
    def get_results(self):
        """
        Get complete detection results
        """
        # Convert sets to lists for JSON serialization
        stats_serializable = dict(self.stats)
        stats_serializable["unique_destinations"] = list(self.stats["unique_destinations"])
        
        return {
            "detection_id": self.detection_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": stats_serializable,
            "alerts": self.alerts,
            "suspicious_flows": self.suspicious_flows,
            "exfiltration_attempts": self.exfil_attempts,
            "summary": {
                "total_alerts": len(self.alerts),
                "high_severity": sum(1 for a in self.alerts if a["severity"] == "high"),
                "medium_severity": sum(1 for a in self.alerts if a["severity"] == "medium"),
                "low_severity": sum(1 for a in self.alerts if a["severity"] == "low"),
                "suspicious_flows": len(self.suspicious_flows)
            }
        }
    
    def generate_report(self, format="json"):
        """
        Generate exfiltration detection report
        """
        results = self.get_results()
        
        if format == "json":
            report_file = f"output/exfiltration/exfil_{self.detection_id}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"[REPORT] JSON report saved to: {report_file}")
            return report_file
        
        elif format == "text":
            # Generate text summary
            lines = []
            lines.append("=" * 60)
            lines.append(f"EXFILTRATION DETECTION REPORT - {self.detection_id}")
            lines.append("=" * 60)
            lines.append("")
            
            # Statistics
            lines.append("📊 STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Total Packets: {self.stats['total_packets']}")
            lines.append(f"Total Bytes: {self.stats['total_bytes']} ({self.stats['total_bytes']/1024/1024:.2f} MB)")
            lines.append(f"Outbound: {self.stats['outbound_bytes']/1024/1024:.2f} MB")
            lines.append(f"Inbound: {self.stats['inbound_bytes']/1024/1024:.2f} MB")
            lines.append(f"Unique Destinations: {len(self.stats['unique_destinations'])}")
            lines.append(f"Total Flows: {self.stats['total_flows']}")
            lines.append("")
            
            # Alerts by severity
            lines.append("🚨 ALERTS SUMMARY")
            lines.append("-" * 40)
            high = sum(1 for a in self.alerts if a["severity"] == "high")
            medium = sum(1 for a in self.alerts if a["severity"] == "medium")
            low = sum(1 for a in self.alerts if a["severity"] == "low")
            lines.append(f"🔴 High Severity: {high}")
            lines.append(f"🟡 Medium Severity: {medium}")
            lines.append(f"🟢 Low Severity: {low}")
            lines.append(f"📊 Total Alerts: {len(self.alerts)}")
            lines.append("")
            
            # Detailed alerts
            if self.alerts:
                lines.append("📋 DETAILED ALERTS")
                lines.append("-" * 40)
                for i, alert in enumerate(self.alerts, 1):
                    severity_symbol = {
                        "high": "🔴",
                        "medium": "🟡",
                        "low": "🟢"
                    }.get(alert["severity"], "⚪")
                    
                    lines.append(f"{severity_symbol} Alert {i}: {alert['type']}")
                    lines.append(f"   {alert['description']}")
                    
                    # Add key details
                    if "details" in alert:
                        for key, value in alert["details"].items():
                            if key not in ["samples", "flows", "transfers"]:
                                lines.append(f"   {key}: {value}")
                    lines.append("")
            
            # Top suspicious flows
            if self.suspicious_flows:
                lines.append("🔍 TOP SUSPICIOUS FLOWS")
                lines.append("-" * 40)
                for flow_key, reason in list(self.suspicious_flows.items())[:5]:
                    lines.append(f"  {flow_key}")
                    lines.append(f"     Reason: {reason.get('reason', 'unknown')}")
                    lines.append(f"     Severity: {reason.get('severity', 'unknown')}")
                    if flow_key in self.flow_bytes:
                        lines.append(f"     Bytes: {self.flow_bytes[flow_key]} ({self.flow_bytes[flow_key]/1024/1024:.2f} MB)")
                    lines.append("")
            
            lines.append("=" * 60)
            
            report_text = "\n".join(lines)
            
            # Save to file
            report_file = f"output/exfiltration/exfil_{self.detection_id}.txt"
            with open(report_file, 'w') as f:
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
        Clean up detector resources
        """
        self.packets = []
        self.flow_bytes.clear()
        self.flow_packets.clear()
        self.flow_timestamps.clear()
        self.destination_stats.clear()
        self.alerts = []
        self.suspicious_flows = {}
        self.logger.info("[CLEAN] Exfiltration detector cleaned up")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()