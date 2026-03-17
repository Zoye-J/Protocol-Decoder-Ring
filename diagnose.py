# diagnose.py - run this from your project root
import json

with open("config/settings.json", "r") as f:
    config = json.load(f)

pc = config.get("packet_capture", {})
print("Interface:", repr(pc.get("interface")))
print("Filter:", repr(pc.get("capture_filter")))
print("Timeout:", pc.get("capture_timeout"))