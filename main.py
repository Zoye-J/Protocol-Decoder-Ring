
"""
Protocol Decoder Ring - Main Entry Point
A network protocol sandbox for analyzing malicious communication patterns
"""

import argparse
import sys
import os
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from modules.sandbox_manager import SandboxManager
from modules.packet_capture import PacketCapture
from modules.protocol_analyzer import ProtocolAnalyzer
from modules.exfiltration_detector import ExfiltrationDetector
from modules.signature_generator import SignatureGenerator
from modules.report_builder import ReportBuilder

class ProtocolDecoderRing:
    """
    Main orchestrator for the Protocol Decoder Ring
    """
    
    def __init__(self, config_path="config/settings.json"):
        self.config_path = config_path
        self.sandbox = None
        self.capture = None
        self.analyzer = None
        self.detector = None
        self.sig_gen = None
        self.report_builder = None
        
    def initialize(self):
        """Initialize all modules"""
        print("""
        ╔══════════════════════════════════════════════════════════╗
        ║    🔐 Protocol Decoder Ring - Network Protocol Sandbox   ║
        ║           Fortinet NSE1/NSE2 Applied Project             ║
        ╚══════════════════════════════════════════════════════════╝
        """)
        
        print("🚀 Initializing modules...")
        
        # Initialize modules in order
        self.sandbox = SandboxManager(self.config_path)
        self.capture = PacketCapture(self.config_path)
        self.analyzer = ProtocolAnalyzer(self.config_path)
        self.detector = ExfiltrationDetector(self.config_path)
        self.sig_gen = SignatureGenerator(self.config_path)
        self.report_builder = ReportBuilder(self.config_path)
        
        print("✅ All modules initialized successfully\n")
        
    def analyze_application(self, app_path, app_args=None):
        """
        Complete analysis pipeline for a suspicious application
        """
        print(f"🔍 Analyzing application: {app_path}")
        
        # Step 1: Create sandbox
        with self.sandbox as sandbox:
            # Step 2: Start packet capture
            self.capture.start_capture()
            
            # Step 3: Run application
            sandbox.run_application(app_path, app_args)
            
            # Step 4: Stop capture and get packets
            packets = self.capture.stop_capture()
            
        # Step 5: Analyze protocols
        protocol_analysis = self.analyzer.analyze(packets)
        
        # Step 6: Detect exfiltration
        exfiltration_alerts = self.detector.detect(protocol_analysis)
        
        # Step 7: Generate signatures
        signatures = self.sig_gen.generate(protocol_analysis, exfiltration_alerts)
        
        # Step 8: Build report
        report = self.report_builder.build(
            app_path=app_path,
            protocol_analysis=protocol_analysis,
            exfiltration_alerts=exfiltration_alerts,
            signatures=signatures
        )
        
        return report
    
    def analyze_pcap(self, pcap_path):
        """
        Analyze an existing PCAP file
        """
        print(f"🔍 Analyzing PCAP file: {pcap_path}")
        
        # Load packets from PCAP
        packets = self.capture.load_pcap(pcap_path)
        
        # Run analysis pipeline
        protocol_analysis = self.analyzer.analyze(packets)
        exfiltration_alerts = self.detector.detect(protocol_analysis)
        signatures = self.sig_gen.generate(protocol_analysis, exfiltration_alerts)
        
        report = self.report_builder.build(
            pcap_path=pcap_path,
            protocol_analysis=protocol_analysis,
            exfiltration_alerts=exfiltration_alerts,
            signatures=signatures
        )
        
        return report

def main():
    parser = argparse.ArgumentParser(description="Protocol Decoder Ring - Network Protocol Sandbox")
    parser.add_argument("--app", help="Path to application to analyze")
    parser.add_argument("--args", nargs="*", help="Arguments for the application")
    parser.add_argument("--pcap", help="Path to PCAP file to analyze")
    parser.add_argument("--config", default="config/settings.json", help="Configuration file path")
    parser.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Create decoder instance
    decoder = ProtocolDecoderRing(args.config)
    decoder.initialize()
    
    # Run analysis
    if args.app:
        report = decoder.analyze_application(args.app, args.args)
    elif args.pcap:
        report = decoder.analyze_pcap(args.pcap)
    else:
        parser.print_help()
        return
    
    # Save report
    report_path = decoder.report_builder.save(report, args.output)
    print(f"\n📊 Report saved to: {report_path}")
    
    # Print summary
    print("\n" + report.get_summary())

if __name__ == "__main__":
    main()