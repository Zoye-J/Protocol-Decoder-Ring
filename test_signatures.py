from modules.signature_generator import SignatureGenerator

fake_protocol_results = {
    "alerts": [
        {
            "type": "c2_beacon_detected",
            "severity": "high",
            "details": {
                "dst_ip": "45.33.22.11",
                "dst_port": 4444,
                "mean_interval": 5.01,
                "flow": "TCP_192.168.1.100:44444-45.33.22.11:4444"
            }
        },
        {
            "type": "possible_dns_tunneling",
            "severity": "high",
            "details": {
                "samples": [
                    {"query": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com"}
                ]
            }
        }
    ]
}

fake_exfil_results = {
    "alerts": [
        {
            "type": "large_data_transfer",
            "severity": "high",
            "details": {
                "transfers": [
                    {"destination": "45.33.22.11", "bytes": 15000000, "megabytes": 14.3}
                ]
            }
        }
    ]
}

generator = SignatureGenerator()
generator.load_analysis_results(
    protocol_analysis=fake_protocol_results,
    exfiltration_results=fake_exfil_results
)
results = generator.generate_signatures()

print(f"\nPatterns extracted: {results['statistics']['patterns_extracted']}")
print(f"Signatures generated: {results['statistics']['signatures_generated']}")
print(f"Formats: {', '.join(results['statistics']['formats_generated'])}")
print(f"\nOutput files:")
for fmt, path in results['output_locations'].items():
    print(f"  {fmt}: {path}")