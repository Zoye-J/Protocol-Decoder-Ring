@echo off
REM Safe test file - simulates C2 beacon traffic for PDR analysis
echo [*] Starting network behavior test...
C:\Users\ASUS\OneDrive\Documents\GitHub\Protocol-Decoder-Ring\venv\Scripts\python.exe -c "
import socket, time
print('[*] Simulating C2 beacon...')
for i in range(8):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(('93.184.216.34', 80))
        s.send(b'GET /beacon HTTP/1.0\r\n\r\n')
        s.close()
    except: pass
    print(f'[*] Beacon {i+1}/8')
    time.sleep(3)

print('[*] Simulating DNS queries...')
domains = ['example.com', 'google.com', 'github.com']
import socket as sk
for d in domains:
    try: sk.gethostbyname(d)
    except: pass
    time.sleep(0.5)
print('[*] Test complete')
"
echo [*] Done
```

This is completely safe — it just makes regular HTTP connections and DNS lookups. The regular 3-second intervals will trigger the C2 beacon detector, and the DNS queries will show up in protocol analysis.

---

## Step 3 — Run the analysis

1. Go to `http://localhost:5000`
2. Click **New Analysis**
3. Upload `test_beacon.bat`
4. Click **Start Analysis**
5. Wait about 35 seconds

---

## Step 4 — Check what you expect to see

**Alerts page should show:**
- `c2_beacon_detected` — HIGH — regular 3-second intervals to `93.184.216.34:80`
- `suspicious_port_usage` — LOW — port 80 traffic
- Possibly `high_entropy_traffic` if any encrypted response comes back
- `timing_pattern` — repeating inter-arrival times

**Signatures page should show:**
- A new Snort `.rules` file with a rule targeting `93.184.216.34`
- A YARA `.yar` file with the destination IP as a string match
- A Sigma `.yml` file for SIEM import

**Reports page should show:**
- A JSON analysis file
- A text report with the full summary

---

## Step 5 — Verify the API directly

Open these URLs in your browser while the dashboard is running:
```
http://localhost:5000/api/v1/status
http://localhost:5000/api/v1/analyses
http://localhost:5000/api/v1/alerts
http://localhost:5000/api/v1/signatures
```

Each should return valid JSON with your test data.

---

## Step 6 — Check the generated Snort rule

After the analysis completes, open the generated rules file:
```
signatures/snort/pdr_rules_siggen_XXXXXXXXXX.rules
```

You should see something like:
```
alert tcp $HOME_NET any -> 93.184.216.34 80
(msg:"PDR - C2_Server_Detection_1000001";
 flags:S;
 metadata: confidence 0.9, pattern_type c2_server;
 sid:1000001; rev:1; priority:1;)