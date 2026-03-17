"""
Module 5: Signature Generator
Automatically creates detection rules based on analyzed malicious traffic patterns
"""

import os
import sys
import json
import time
import hashlib
import re
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path
import logging

# Try to import yaml for Sigma rules
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'


class SignatureGenerator:
    """
    Generates detection signatures in various formats based on traffic analysis
    """
    
    # Template for Snort rules
    # Replace multiline template with single line:
    SNORT_TEMPLATE = ('alert {protocol} {src_net} {src_port} -> {dst_net} {dst_port} '
                    '(msg:"PDR - {rule_name}"; {content_rules} {metadata} '
                    'sid:{sid}; rev:1; priority:{priority};)')
    
    # Template for Suricata rules (compatible with Snort)
    SURICATA_TEMPLATE = """
alert {protocol} {src_net} {src_port} -> {dst_net} {dst_port} 
(msg:"PDR - {rule_name}"; 
 {content_rules}
 {metadata}
 classtype:{classtype}; sid:{sid}; rev:1; priority:{priority};)
"""
    
    # Template for YARA rules
    YARA_TEMPLATE = """
rule {rule_name} {{
    meta:
        description = "{description}"
        author = "PDR"
        date = "{date}"
        severity = "{severity}"
        reference = "internal_analysis_{analysis_id}"
    
    strings:
{strings}
    
    condition:
        {condition}
}}
"""
    
    # Template for Sigma rules
    SIGMA_TEMPLATE = """
title: {title}
id: {rule_id}
status: experimental
description: '{description}'
author: PDR
date: {date}
modified: {date}

logsource:
    product: {product}
    category: {category}

detection:
    selection:
{selection}
    condition: selection

falsepositives:
    - Unknown

level: {level}
"""
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the signature generator
        """
        self.generator_id = self._generate_generator_id()
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Signature storage
        self.signatures = {
            "snort": [],
            "suricata": [],
            "yara": [],
            "sigma": [],
            "custom_json": []
        }
        
        # Analysis results (input)
        self.protocol_analysis = None
        self.exfiltration_results = None
        self.packets = []
        
        # Pattern extraction
        self.extracted_patterns = {
            "byte_sequences": [],
            "domain_patterns": [],
            "ip_patterns": [],
            "port_patterns": [],
            "timing_patterns": [],
            "size_patterns": []
        }
        
        # Statistics
        self.stats = {
            "start_time": None,
            "end_time": None,
            "patterns_extracted": 0,
            "signatures_generated": 0,
            "formats_generated": []
        }
        
        # Create output directories
        os.makedirs("signatures/snort", exist_ok=True)
        os.makedirs("signatures/suricata", exist_ok=True)
        os.makedirs("signatures/yara", exist_ok=True)
        os.makedirs("signatures/sigma", exist_ok=True)
        os.makedirs("signatures/custom", exist_ok=True)
        
        self.logger.info(f"[TOOL] SignatureGenerator initialized with ID: {self.generator_id}")
    
    def _generate_generator_id(self) -> str:
        """Generate unique generator ID"""
        return f"siggen_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for signature generator"""
        logger = logging.getLogger(f"SignatureGenerator.{self.generator_id}")
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
            fh = logging.FileHandler(f"logs/signature_{self.generator_id}.log", encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"⚠️  Could not create log file: {e}")
        
        return logger
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        default_config = {
            "signature_generation": {
                "output_dir": "signatures",
                "snort_version": "2.9",
                "suricata_compatible": True,
                "yara_rules": True,
                "sigma_rules": True,
                "min_confidence": 0.7,
                "max_signatures_per_pattern": 5,
                "include_payload": True,
                "include_metadata": True,
                "default_priority": 2,
                "signature_author": "PDR"
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if "signature_generation" in config:
                        return config["signature_generation"]
                    return default_config["signature_generation"]
            else:
                print(f"[WARN] Config file not found at {config_path}, using defaults")
                return default_config["signature_generation"]
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return default_config["signature_generation"]
    
    def load_analysis_results(self, protocol_analysis=None, exfiltration_results=None, packets=None):
        """
        Load results from previous modules for signature generation
        """
        if protocol_analysis:
            self.protocol_analysis = protocol_analysis
            self.logger.info(f"[LOAD] Loaded protocol analysis with {len(protocol_analysis.get('alerts', []))} alerts")
        
        if exfiltration_results:
            self.exfiltration_results = exfiltration_results
            self.logger.info(f"[LOAD] Loaded exfiltration results with {len(exfiltration_results.get('alerts', []))} alerts")
        
        if packets:
            self.packets = packets
            self.logger.info(f"[LOAD] Loaded {len(packets)} packets for pattern extraction")
    
    def generate_signatures(self):
        """
        Generate signatures from all loaded analysis results
        """
        self.logger.info("[GENERATE] Starting signature generation...")
        self.stats["start_time"] = time.time()
        
        if not self.protocol_analysis and not self.exfiltration_results:
            self.logger.warning("[WARN] No analysis results loaded")
            return {}
        
        # Step 1: Extract patterns from alerts and packets
        self._extract_patterns_from_alerts()
        self._extract_patterns_from_packets()
        
        # Step 2: Generate signatures for each format
        if self.config.get("snort_version"):
            self._generate_snort_signatures()
        
        if self.config.get("suricata_compatible"):
            self._generate_suricata_signatures()
        
        if self.config.get("yara_rules"):
            self._generate_yara_signatures()
        
        if self.config.get("sigma_rules") and YAML_AVAILABLE:
            self._generate_sigma_signatures()
        
        self._generate_custom_json_signatures()
        
        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        self.logger.info(f"[COMPLETE] Signature generation completed in {duration:.2f}s")
        self.logger.info(f"           Patterns extracted: {self.stats['patterns_extracted']}")
        self.logger.info(f"           Signatures generated: {self.stats['signatures_generated']}")
        self.logger.info(f"           Formats: {', '.join(self.stats['formats_generated'])}")
        
        return self.get_results()
    
    def _extract_patterns_from_alerts(self):
        """
        Extract patterns from analysis alerts
        """
        self.logger.info("[PATTERNS] Extracting patterns from alerts...")
        
        alerts = []
        
        # Collect alerts from both sources
        if self.protocol_analysis:
            alerts.extend(self.protocol_analysis.get('alerts', []))
        if self.exfiltration_results:
            alerts.extend(self.exfiltration_results.get('alerts', []))
        
        if not alerts:
            self.logger.info("[PATTERNS] No alerts to extract patterns from")
            return
        
        # Process each alert
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            severity = alert.get('severity', 'medium')
            details = alert.get('details', {})
            
            # Extract patterns based on alert type
            if 'dns' in alert_type.lower():
                self._extract_dns_patterns(alert, details)
            elif 'c2' in alert_type.lower() or 'beacon' in alert_type.lower():
                self._extract_c2_patterns(alert, details)
            elif 'http' in alert_type.lower():
                self._extract_http_patterns(alert, details)
            elif 'covert' in alert_type.lower() or 'channel' in alert_type.lower():
                self._extract_covert_patterns(alert, details)
            elif 'exfil' in alert_type.lower() or 'transfer' in alert_type.lower():
                self._extract_exfil_patterns(alert, details)
        
        self.stats['patterns_extracted'] = sum(len(p) for p in self.extracted_patterns.values())
    
    def _extract_dns_patterns(self, alert, details):
        """
        Extract DNS-specific patterns
        """
        # Extract long domain names
        samples = details.get('samples', [])
        suspicious_queries = details.get('suspicious_queries', [])
        
        for item in samples + suspicious_queries:
            if isinstance(item, dict):
                query = item.get('query', '')
                if query and len(query) > 30:
                    # Extract domain pattern with regex
                    # Convert specific domain to pattern with wildcards
                    domain_parts = query.split('.')
                    if len(domain_parts) > 2:
                        # Pattern: [a-z0-9]{50,}.example.com
                        pattern = '.'.join(['[a-z0-9]{50,}' if len(p) > 20 else re.escape(p) 
                                           for p in domain_parts])
                        self.extracted_patterns['domain_patterns'].append({
                            'pattern': pattern,
                            'original': query,
                            'type': 'dns_tunneling',
                            'confidence': 0.8
                        })
    
    def _extract_c2_patterns(self, alert, details):
        """
        Extract C2 beacon patterns
        """
        flow = details.get('flow', '')
        dst_ip = details.get('dst_ip', '')
        dst_port = details.get('dst_port', 0)
        mean_interval = details.get('mean_interval', 0)
        
        if dst_ip and dst_port:
            self.extracted_patterns['ip_patterns'].append({
                'ip': dst_ip,
                'port': dst_port,
                'type': 'c2_server',
                'confidence': 0.9,
                'metadata': {
                    'mean_interval': mean_interval,
                    'flow': flow
                }
            })
    
    def _extract_http_patterns(self, alert, details):
        """
        Extract HTTP-based patterns
        """
        samples = details.get('samples', [])
        suspicious_flows = details.get('suspicious_flows', [])
        
        for item in samples + suspicious_flows:
            if isinstance(item, dict):
                uri = item.get('info', '')
                if uri and len(uri) > 50:
                    # Extract URI pattern
                    # Replace variable parts with wildcards
                    pattern = re.sub(r'[0-9]{4,}', '[0-9]+', uri)
                    pattern = re.sub(r'[a-f0-9]{32,}', '[a-f0-9]+', pattern)
                    
                    self.extracted_patterns['byte_sequences'].append({
                        'pattern': pattern[:100],
                        'type': 'http_exfil',
                        'confidence': 0.7
                    })
    
    def _extract_covert_patterns(self, alert, details):
        """
        Extract covert channel patterns
        """
        flow = details.get('flow', '')
        packet_size = details.get('packet_size', 0)
        
        if packet_size > 0:
            self.extracted_patterns['size_patterns'].append({
                'size': packet_size,
                'flow': flow,
                'type': 'covert_fixed_size',
                'confidence': 0.9
            })
        
        # Extract timing patterns
        mean_interval = details.get('mean_interval', 0)
        if mean_interval > 0:
            self.extracted_patterns['timing_patterns'].append({
                'interval': mean_interval,
                'flow': flow,
                'type': 'timing_channel',
                'confidence': 0.85
            })
    
    def _extract_exfil_patterns(self, alert, details):
        """
        Extract exfiltration patterns
        """
        transfers = details.get('transfers', [])
        
        for transfer in transfers:
            if isinstance(transfer, dict):
                dest = transfer.get('destination', '')
                if dest:
                    self.extracted_patterns['ip_patterns'].append({
                        'ip': dest,
                        'type': 'exfiltration_destination',
                        'confidence': 0.75
                    })
    
    def _extract_patterns_from_packets(self):
        """
        Extract patterns directly from packet payloads
        """
        if not self.packets or not self.config.get('include_payload', True):
            return
        
        self.logger.info("[PATTERNS] Extracting patterns from packet payloads...")
        
        # Collect unique byte sequences from suspicious packets
        byte_sequences = []
        
        for packet in self.packets:
            if not isinstance(packet, dict):
                continue
            
            # Get raw data
            raw_data = packet.get('raw_data', b'')
            if isinstance(raw_data, str):
                raw_data = raw_data.encode('utf-8', errors='ignore')
            
            if len(raw_data) < 8:  # Skip very short payloads
                continue
            
            # Look for repeating patterns
            # This is a simplified approach - in production, you'd use more sophisticated analysis
            
            # Check for common malware patterns
            patterns_to_check = [
                (b'\x00\x00\x00\x00', 'null_bytes'),
                (b'\x90\x90\x90\x90', 'nop_sled'),
                (b'\xcc\xcc\xcc\xcc', 'int3_break'),
                (b'\x41\x41\x41\x41', 'repeating_a'),
                (b'\x00' * 10, 'long_null'),
            ]
            
            for pattern, pattern_name in patterns_to_check:
                if pattern in raw_data:
                    # Extract a signature (first 20 bytes of the area around pattern)
                    pos = raw_data.find(pattern)
                    start = max(0, pos - 10)
                    end = min(len(raw_data), pos + len(pattern) + 20)
                    signature = raw_data[start:end]
                    
                    # Convert to hex string for signature
                    hex_str = ' '.join(f'{b:02x}' for b in signature)
                    
                    byte_sequences.append({
                        'pattern': hex_str,
                        'type': pattern_name,
                        'confidence': 0.6,
                        'length': len(signature)
                    })
        
        # Add unique sequences
        seen = set()
        for seq in byte_sequences:
            if seq['pattern'] not in seen:
                seen.add(seq['pattern'])
                self.extracted_patterns['byte_sequences'].append(seq)
    
    def _generate_snort_signatures(self):
        """
        Generate Snort IDS rules from extracted patterns
        """
        self.logger.info("[SNORT] Generating Snort signatures...")
        
        if not self.extracted_patterns:
            self.logger.warning("[SNORT] No patterns to generate signatures")
            return
        
        sid_base = 1000000  # Base SID for custom rules
        signatures = []
        
        # Generate signatures for each pattern type
        for pattern_type, patterns in self.extracted_patterns.items():
            for i, pattern in enumerate(patterns[:self.config.get('max_signatures_per_pattern', 5)]):
                confidence = pattern.get('confidence', 0.5)
                
                if confidence < self.config.get('min_confidence', 0.7):
                    continue
                
                # Determine rule parameters based on pattern type
                if pattern_type == 'domain_patterns':
                    rule = self._create_snort_dns_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'ip_patterns':
                    rule = self._create_snort_ip_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'byte_sequences':
                    rule = self._create_snort_byte_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'size_patterns':
                    rule = self._create_snort_size_rule(pattern, sid_base + len(signatures))
                else:
                    continue
                
                if rule:
                    signatures.append(rule)
        
        if signatures:
            # Save to file
            filename = f"signatures/snort/pdr_rules_{self.generator_id}.rules"
            with open(filename, 'w') as f:
                f.write("# PDR Generated Snort Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Analysis ID: {self.generator_id}\n")
                f.write("# " + "=" * 50 + "\n\n")
                
                for rule in signatures:
                    f.write(rule.strip() + "\n\n")
            
            self.signatures['snort'] = signatures
            self.stats['signatures_generated'] += len(signatures)
            self.stats['formats_generated'].append('snort')
            self.logger.info(f"[SNORT] Generated {len(signatures)} signatures")
    
    def _create_snort_dns_rule(self, pattern, sid):
        """
        Create Snort rule for DNS patterns
        """
        domain_pattern = pattern.get('pattern', '')
        confidence = pattern.get('confidence', 0.5)
        
        # Map confidence to priority (1-3, lower is higher priority)
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        # Create content rule for DNS
        content_rules = 'content:"|01 00 00 01|"; depth:4; '  # DNS query header
        
        if domain_pattern:
            # Add content match for domain pattern
            content_rules += f'content:"{domain_pattern}"; nocase; '
        
        metadata = f'metadata: confidence {confidence}, pattern_type dns_tunneling;'
        
        rule_name = f"DNS_Tunneling_Detection_{sid}"
        
        rule = self.SNORT_TEMPLATE.format(
            protocol="udp",
            src_net="$HOME_NET",
            src_port="any",
            dst_net="$EXTERNAL_NET",
            dst_port="53",
            rule_name=rule_name,
            content_rules=content_rules,
            metadata=metadata,
            sid=sid,
            priority=priority
        )
        
        return rule
    
    def _create_snort_ip_rule(self, pattern, sid):
        """
        Create Snort rule for IP-based patterns
        """
        ip = pattern.get('ip', '')
        port = pattern.get('port', 0)
        confidence = pattern.get('confidence', 0.5)
        
        if not ip:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        # Create rule for specific IP
        dst_net = ip
        dst_port = str(port) if port else "any"
        
        content_rules = ""
        if port:
            content_rules = f'flags:S; '  # Check for SYN flag
        
        metadata = f'metadata: confidence {confidence}, pattern_type c2_server;'
        
        rule_name = f"C2_Server_Detection_{sid}"
        
        rule = self.SNORT_TEMPLATE.format(
            protocol="tcp",
            src_net="$HOME_NET",
            src_port="any",
            dst_net=dst_net,
            dst_port=dst_port,
            rule_name=rule_name,
            content_rules=content_rules,
            metadata=metadata,
            sid=sid,
            priority=priority
        )
        
        return rule
    
    def _create_snort_byte_rule(self, pattern, sid):
        """
        Create Snort rule for byte sequence patterns
        """
        byte_pattern = pattern.get('pattern', '')
        pattern_type = pattern.get('type', 'unknown')
        confidence = pattern.get('confidence', 0.5)
        
        if not byte_pattern:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        # Content rule with hex bytes
        content_rules = f'content:"{byte_pattern}"; '
        
        metadata = f'metadata: confidence {confidence}, pattern_type {pattern_type};'
        
        rule_name = f"Malicious_Pattern_{sid}"
        
        rule = self.SNORT_TEMPLATE.format(
            protocol="tcp",
            src_net="$HOME_NET",
            src_port="any",
            dst_net="$EXTERNAL_NET",
            dst_port="any",
            rule_name=rule_name,
            content_rules=content_rules,
            metadata=metadata,
            sid=sid,
            priority=priority
        )
        
        return rule
    
    def _create_snort_size_rule(self, pattern, sid):
        """
        Create Snort rule for packet size patterns
        """
        size = pattern.get('size', 0)
        confidence = pattern.get('confidence', 0.5)
        
        if not size:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        # Use dsize keyword for packet size
        content_rules = f'dsize:{size}; '
        
        metadata = f'metadata: confidence {confidence}, pattern_type covert_channel;'
        
        rule_name = f"Covert_Channel_Size_{sid}"
        
        rule = self.SNORT_TEMPLATE.format(
            protocol="tcp",
            src_net="$HOME_NET",
            src_port="any",
            dst_net="$EXTERNAL_NET",
            dst_port="any",
            rule_name=rule_name,
            content_rules=content_rules,
            metadata=metadata,
            sid=sid,
            priority=priority
        )
        
        return rule
    

    def _create_suricata_dns_rule(self, pattern, sid):
        """Create Suricata rule for DNS patterns"""
        domain_pattern = pattern.get('pattern', '')
        confidence = pattern.get('confidence', 0.5)
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        content_rules = 'dns.query; '
        if domain_pattern:
            content_rules += f'content:"{domain_pattern}"; nocase; '
        
        rule = (
            f'alert dns $HOME_NET any -> any 53 '
            f'(msg:"PDR - DNS_Tunneling_{sid}"; '
            f'{content_rules}'
            f'metadata: confidence {confidence}; '
            f'classtype:policy-violation; sid:{sid}; rev:1; priority:{priority};)'
        )
        return rule

    def _create_suricata_ip_rule(self, pattern, sid):
        """Create Suricata rule for IP/C2 patterns"""
        ip = pattern.get('ip', '')
        port = pattern.get('port', 0)
        confidence = pattern.get('confidence', 0.5)
        
        if not ip:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        dst_port = str(port) if port else 'any'
        
        rule = (
            f'alert tcp $HOME_NET any -> {ip} {dst_port} '
            f'(msg:"PDR - C2_Server_{sid}"; '
            f'flags:S; '
            f'metadata: confidence {confidence}; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; priority:{priority};)'
        )
        return rule

    def _create_suricata_byte_rule(self, pattern, sid):
        """Create Suricata rule for byte sequence patterns"""
        byte_pattern = pattern.get('pattern', '')
        pattern_type = pattern.get('type', 'unknown')
        confidence = pattern.get('confidence', 0.5)
        
        if not byte_pattern:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        rule = (
            f'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"PDR - Malicious_Pattern_{sid}"; '
            f'content:"{byte_pattern}"; '
            f'metadata: confidence {confidence}, pattern_type {pattern_type}; '
            f'classtype:malware-cnc; sid:{sid}; rev:1; priority:{priority};)'
        )
        return rule

    def _create_suricata_size_rule(self, pattern, sid):
        """Create Suricata rule for packet size patterns"""
        size = pattern.get('size', 0)
        confidence = pattern.get('confidence', 0.5)
        
        if not size:
            return None
        
        priority = 1 if confidence > 0.9 else (2 if confidence > 0.7 else 3)
        
        rule = (
            f'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"PDR - Covert_Channel_Size_{sid}"; '
            f'dsize:{size}; '
            f'metadata: confidence {confidence}, pattern_type covert_channel; '
            f'classtype:policy-violation; sid:{sid}; rev:1; priority:{priority};)'
        )
        return rule
    
    def _generate_suricata_signatures(self):
        """
        Generate Suricata-compatible signatures directly from extracted patterns
        """
        self.logger.info("[SURICATA] Generating Suricata signatures...")
        
        if not self.extracted_patterns:
            self.logger.warning("[SURICATA] No patterns to generate signatures")
            return
        
        sid_base = 2000000  # Different base SID to avoid conflicts with Snort
        signatures = []
        
        # Generate signatures for each pattern type
        for pattern_type, patterns in self.extracted_patterns.items():
            for i, pattern in enumerate(patterns[:self.config.get('max_signatures_per_pattern', 5)]):
                confidence = pattern.get('confidence', 0.5)
                
                if confidence < self.config.get('min_confidence', 0.7):
                    continue
                
                # Determine rule parameters based on pattern type
                if pattern_type == 'domain_patterns':
                    rule = self._create_suricata_dns_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'ip_patterns':
                    rule = self._create_suricata_ip_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'byte_sequences':
                    rule = self._create_suricata_byte_rule(pattern, sid_base + len(signatures))
                elif pattern_type == 'size_patterns':
                    rule = self._create_suricata_size_rule(pattern, sid_base + len(signatures))
                else:
                    continue
                
                if rule:
                    signatures.append(rule)
        
        if signatures:
            # Save to file
            filename = f"signatures/suricata/pdr_rules_{self.generator_id}.rules"
            with open(filename, 'w') as f:
                f.write("# PDR Generated Suricata Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Analysis ID: {self.generator_id}\n")
                f.write("# " + "=" * 50 + "\n\n")
                
                for rule in signatures:
                    f.write(rule.strip() + "\n\n")
            
            self.signatures['suricata'] = signatures
            self.stats['signatures_generated'] += len(signatures)
            self.stats['formats_generated'].append('suricata')
            self.logger.info(f"[SURICATA] Generated {len(signatures)} signatures")
        else:
            self.logger.info("[SURICATA] No signatures generated")
    
    def _generate_yara_signatures(self):
        """
        Generate YARA rules from extracted patterns
        """
        self.logger.info("[YARA] Generating YARA signatures...")
        
        if not self.extracted_patterns:
            self.logger.warning("[YARA] No patterns to generate signatures")
            return
        
        signatures = []
        
        # Generate YARA for DNS tunneling
        if self.extracted_patterns['domain_patterns']:
            rule = self._create_yara_dns_rule()
            if rule:
                signatures.append(rule)
        
        # Generate YARA for byte sequences
        if self.extracted_patterns['byte_sequences']:
            rule = self._create_yara_byte_rule()
            if rule:
                signatures.append(rule)
        
        # Generate YARA for C2 patterns
        if self.extracted_patterns['ip_patterns']:
            rule = self._create_yara_c2_rule()
            if rule:
                signatures.append(rule)
        
        if signatures:
            # Save to file
            filename = f"signatures/yara/pdr_rules_{self.generator_id}.yar"
            with open(filename, 'w') as f:
                f.write("/* PDR Generated YARA Rules */\n")
                f.write(f"/* Generated: {datetime.now().isoformat()} */\n")
                f.write(f"/* Analysis ID: {self.generator_id} */\n")
                f.write("/* " + "=" * 50 + " */\n\n")
                
                for rule in signatures:
                    f.write(rule + "\n")
            
            self.signatures['yara'] = signatures
            self.stats['signatures_generated'] += len(signatures)
            self.stats['formats_generated'].append('yara')
            self.logger.info(f"[YARA] Generated {len(signatures)} signatures")
    
    def _create_yara_dns_rule(self):
        """
        Create YARA rule for DNS tunneling detection
        """
        # Extract domain patterns
        domain_patterns = self.extracted_patterns['domain_patterns']
        
        if not domain_patterns:
            return None
        
        # Create strings section
        strings = []
        for i, pattern in enumerate(domain_patterns[:5]):  # Limit to 5 patterns
            original = pattern.get('original', '')
            if original:
                # Escape for YARA
                escaped = original.replace('"', '\\"')
                strings.append(f'        $dns_pattern_{i} = "{escaped}" nocase')
        
        if not strings:
            return None
        
        # Create condition
        condition = "any of them"
        
        rule = self.YARA_TEMPLATE.format(
            rule_name="PDR_DNS_Tunneling",
            description="Detects potential DNS tunneling activity",
            author=self.config.get('signature_author', 'PDR'),
            date=datetime.now().strftime('%Y-%m-%d'),
            severity="high",
            analysis_id=self.generator_id,
            strings="\n".join(strings),
            condition=condition
        )
        
        return rule
    
    def _create_yara_byte_rule(self):
        """
        Create YARA rule for malicious byte sequences
        """
        byte_patterns = self.extracted_patterns['byte_sequences']
        
        if not byte_patterns:
            return None
        
        # Create strings section with hex patterns
        strings = []
        for i, pattern in enumerate(byte_patterns[:10]):  # Limit to 10 patterns
            hex_pattern = pattern.get('pattern', '')
            if hex_pattern:
                # Convert hex string to YARA hex format
                # Remove spaces and add curly braces
                hex_pattern = hex_pattern.replace(' ', '')
                strings.append(f'        $byte_pattern_{i} = {{{hex_pattern}}}')
        
        if not strings:
            return None
        
        # Create condition - any of the patterns
        condition = "any of them"
        
        rule = self.YARA_TEMPLATE.format(
            rule_name="PDR_Malicious_Patterns",
            description="Detects known malicious byte sequences",
            author=self.config.get('signature_author', 'PDR'),
            date=datetime.now().strftime('%Y-%m-%d'),
            severity="medium",
            analysis_id=self.generator_id,
            strings="\n".join(strings),
            condition=condition
        )
        
        return rule
    
    def _create_yara_c2_rule(self):
        """
        Create YARA rule for C2 communication patterns
        """
        ip_patterns = self.extracted_patterns['ip_patterns']
        
        if not ip_patterns:
            return None
        
        # Create strings section with IP addresses as strings
        strings = []
        for i, pattern in enumerate(ip_patterns[:5]):
            ip = pattern.get('ip', '')
            if ip:
                strings.append(f'        $c2_ip_{i} = "{ip}" ascii')
        
        if not strings:
            return None
        
        # Create condition
        condition = "any of them"
        
        rule = self.YARA_TEMPLATE.format(
            rule_name="PDR_C2_Servers",
            description="Detects communication with known C2 servers",
            author=self.config.get('signature_author', 'PDR'),
            date=datetime.now().strftime('%Y-%m-%d'),
            severity="high",
            analysis_id=self.generator_id,
            strings="\n".join(strings),
            condition=condition
        )
        
        return rule
    
    def _generate_sigma_signatures(self):
        """
        Generate Sigma rules for SIEM integration
        """
        if not YAML_AVAILABLE:
            self.logger.warning("[SIGMA] PyYAML not installed, skipping Sigma rules")
            return
        
        self.logger.info("[SIGMA] Generating Sigma signatures...")
        
        signatures = []
        
        # Generate Sigma for DNS tunneling
        if self.extracted_patterns['domain_patterns']:
            rule = self._create_sigma_dns_rule()
            if rule:
                signatures.append(rule)
        
        # Generate Sigma for C2 detection
        if self.extracted_patterns['ip_patterns']:
            rule = self._create_sigma_c2_rule()
            if rule:
                signatures.append(rule)
        
        # Generate Sigma for data exfiltration
        if self.extracted_patterns['size_patterns']:
            rule = self._create_sigma_exfil_rule()
            if rule:
                signatures.append(rule)
        
        if signatures:
            # Save to file
            filename = f"signatures/sigma/pdr_rules_{self.generator_id}.yml"
            with open(filename, 'w') as f:
                f.write("# PDR Generated Sigma Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Analysis ID: {self.generator_id}\n")
                f.write("# " + "=" * 50 + "\n\n")
                
                for rule in signatures:
                    f.write(rule + "\n")
            
            self.signatures['sigma'] = signatures
            self.stats['signatures_generated'] += len(signatures)
            self.stats['formats_generated'].append('sigma')
            self.logger.info(f"[SIGMA] Generated {len(signatures)} signatures")
    
    def _create_sigma_dns_rule(self):
        """
        Create Sigma rule for DNS tunneling detection
        """
        rule_id = hashlib.md5(f"dns_tunnel_{self.generator_id}".encode()).hexdigest()[:8]
        rule_id = f"pdr-{rule_id}"
        
        # Create selection criteria
        selection = """
            EventID: 22
            Protocol: udp
            DestinationPort: 53
            Query|re: '[a-z0-9]{50,}\\..*'"""
        
        rule = self.SIGMA_TEMPLATE.format(
            title="DNS Tunneling Detection",
            rule_id=rule_id,
            description="Detects possible DNS tunneling based on long domain names",
            date=datetime.now().strftime('%Y/%m/%d'),
            product="windows",
            category="dns_query",
            selection=selection,
            level="high"
        )
        
        return rule
    
    def _create_sigma_c2_rule(self):
        """
        Create Sigma rule for C2 detection
        """
        rule_id = hashlib.md5(f"c2_detection_{self.generator_id}".encode()).hexdigest()[:8]
        rule_id = f"pdr-{rule_id}"
        
        # Extract C2 IPs
        c2_ips = [p.get('ip', '') for p in self.extracted_patterns['ip_patterns'] 
                 if p.get('type') == 'c2_server'][:3]
        
        if not c2_ips:
            return None
        
        # Create selection with IPs
        ip_conditions = '\n'.join([f'            DestinationIp: {ip}' for ip in c2_ips])
        selection = f"""
    selection:
        {ip_conditions}
        DestinationPort:
            - 4444
            - 5555
            - 6667
            - 8080"""
        
        rule = self.SIGMA_TEMPLATE.format(
            title="C2 Server Communication",
            rule_id=rule_id,
            description="Detects communication with known C2 infrastructure",
            date=datetime.now().strftime('%Y/%m/%d'),
            product="windows",
            category="network_connection",
            selection=selection,
            level="critical"
        )
        
        return rule
    
    def _create_sigma_exfil_rule(self):
        """
        Create Sigma rule for data exfiltration detection
        """
        rule_id = hashlib.md5(f"exfil_detection_{self.generator_id}".encode()).hexdigest()[:8]
        rule_id = f"pdr-{rule_id}"
        
        selection = """
    selection:
        EventID: 3
        Initiated: true
        BytesSent|gte: 10485760  # 10MB"""
        
        rule = self.SIGMA_TEMPLATE.format(
            title="Large Data Transfer",
            rule_id=rule_id,
            description="Detects large outbound data transfers (possible exfiltration)",
            date=datetime.now().strftime('%Y/%m/%d'),
            product="windows",
            category="network_connection",
            selection=selection,
            level="high"
        )
        
        return rule
    
    def _generate_custom_json_signatures(self):
        """
        Generate custom JSON signatures for internal use
        """
        self.logger.info("[JSON] Generating custom JSON signatures...")
        
        signatures = []
        
        # Create a comprehensive JSON signature
        json_sig = {
            "signature_id": f"PDR-{self.generator_id}",
            "generated": datetime.now().isoformat(),
            "analysis_id": self.generator_id,
            "patterns": self.extracted_patterns,
            "rules": {
                "snort_count": len(self.signatures['snort']),
                "suricata_count": len(self.signatures['suricata']),
                "yara_count": len(self.signatures['yara']),
                "sigma_count": len(self.signatures['sigma'])
            },
            "threat_intel": {
                "c2_servers": [p for p in self.extracted_patterns['ip_patterns'] 
                              if p.get('type') == 'c2_server'],
                "exfil_destinations": [p for p in self.extracted_patterns['ip_patterns'] 
                                      if p.get('type') == 'exfiltration_destination'],
                "dns_patterns": self.extracted_patterns['domain_patterns'],
                "byte_signatures": self.extracted_patterns['byte_sequences'][:10]
            }
        }
        
        signatures.append(json_sig)
        
        # Save to file
        filename = f"signatures/custom/pdr_signatures_{self.generator_id}.json"
        with open(filename, 'w') as f:
            json.dump(json_sig, f, indent=2, default=str)
        
        self.signatures['custom_json'] = signatures
        self.stats['signatures_generated'] += 1
        self.stats['formats_generated'].append('custom_json')
        self.logger.info(f"[JSON] Generated custom JSON signature")
    
    def get_results(self):
        """
        Get complete signature generation results
        """
        return {
            "generator_id": self.generator_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": self.stats,
            "patterns_extracted": self.extracted_patterns,
            "signatures": {
                format_name: len(sigs) for format_name, sigs in self.signatures.items()
            },
            "output_locations": {
                "snort": f"signatures/snort/pdr_rules_{self.generator_id}.rules",
                "suricata": f"signatures/suricata/pdr_rules_{self.generator_id}.rules",
                "yara": f"signatures/yara/pdr_rules_{self.generator_id}.yar",
                "sigma": f"signatures/sigma/pdr_rules_{self.generator_id}.yml",
                "custom": f"signatures/custom/pdr_signatures_{self.generator_id}.json"
            }
        }
    
    def generate_report(self, format="json"):
        """
        Generate signature generation report
        """
        results = self.get_results()
        
        if format == "json":
            report_file = f"signatures/custom/report_{self.generator_id}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"[REPORT] JSON report saved to: {report_file}")
            return report_file
        
        elif format == "text":
            # Generate text summary
            lines = []
            lines.append("=" * 60)
            lines.append(f"SIGNATURE GENERATION REPORT - {self.generator_id}")
            lines.append("=" * 60)
            lines.append("")
            
            # Statistics
            lines.append("📊 STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Patterns Extracted: {self.stats['patterns_extracted']}")
            lines.append(f"Signatures Generated: {self.stats['signatures_generated']}")
            lines.append(f"Formats: {', '.join(self.stats['formats_generated'])}")
            lines.append(f"Generation Time: {self.stats.get('end_time', 0) - self.stats.get('start_time', 0):.2f}s")
            lines.append("")
            
            # Patterns by type
            lines.append("🔍 EXTRACTED PATTERNS")
            lines.append("-" * 40)
            for pattern_type, patterns in self.extracted_patterns.items():
                if patterns:
                    lines.append(f"  {pattern_type}: {len(patterns)}")
                    # Show samples
                    for pattern in patterns[:2]:
                        if 'ip' in pattern:
                            lines.append(f"    - {pattern.get('ip', '')}:{pattern.get('port', 'any')} ({pattern.get('type', 'unknown')})")
                        elif 'pattern' in pattern:
                            p = pattern.get('pattern', '')
                            if len(p) > 50:
                                p = p[:50] + "..."
                            lines.append(f"    - {p}")
            lines.append("")
            
            # Signatures generated
            lines.append("📝 SIGNATURES GENERATED")
            lines.append("-" * 40)
            for format_name, sigs in self.signatures.items():
                if sigs:
                    lines.append(f"  {format_name.upper()}: {len(sigs)} signatures")
                    lines.append(f"    File: signatures/{format_name}/pdr_rules_{self.generator_id}.{format_name}")
            lines.append("")
            
            # Sample rules
            if self.signatures['snort']:
                lines.append("📋 SAMPLE SNORT RULE")
                lines.append("-" * 40)
                sample = self.signatures['snort'][0].strip()
                lines.append(sample)
                lines.append("")
            
            lines.append("=" * 60)
            
            report_text = "\n".join(lines)
            
            # Save to file
            report_file = f"signatures/custom/report_{self.generator_id}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            
            self.logger.info(f"[REPORT] Text report saved to: {report_file}")
            return report_file
        
        return results
    
    def cleanup(self):
        """
        Clean up generator resources
        """
        self.extracted_patterns.clear()
        self.signatures = {k: [] for k in self.signatures}
        self.logger.info("[CLEAN] Signature generator cleaned up")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()