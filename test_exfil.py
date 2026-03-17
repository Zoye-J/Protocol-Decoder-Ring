import time
from modules.exfiltration_detector import ExfiltrationDetector

sample_packets = []

# Normal outbound traffic
for i in range(20):
    sample_packets.append({
        "time": time.time() + i,
        "length": 500,
        "protocol": "TCP",
        "src": "192.168.1.100",
        "dst": "8.8.8.8",
        "sport": 54321,
        "dport": 80,
        "info": "HTTP GET"
    })

# Covert channel — fixed size ICMP
for i in range(25):
    sample_packets.append({
        "time": time.time() + 30 + i,
        "length": 64,
        "protocol": "ICMP",
        "src": "192.168.1.100",
        "dst": "45.33.22.11",
        "sport": 0,
        "dport": 0,
        "info": "ICMP Echo"
    })

# DNS exfiltration — many queries to port 53
for i in range(60):
    sample_packets.append({
        "time": time.time() + 60 + i * 0.5,
        "length": 80,
        "protocol": "UDP",
        "src": "192.168.1.100",
        "dst": "8.8.8.8",
        "sport": 12345,
        "dport": 53,
        "info": f"DNS Query: {'a'*20}.evil.com"
    })

detector = ExfiltrationDetector()
detector.load_packets(sample_packets)
results = detector.detect_exfiltration()

print(f"\nTotal alerts: {results['summary']['total_alerts']}")
print(f"High severity: {results['summary']['high_severity']}")
print(f"Suspicious flows: {results['summary']['suspicious_flows']}")
print(f"\nALERTS:")
for alert in results['alerts']:
    print(f"  [{alert['severity'].upper()}] {alert['type']}")
    print(f"     {alert['description']}")

detector.generate_report("text")
print("\nReport saved to output/exfiltration/")