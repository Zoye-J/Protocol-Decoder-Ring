@echo off
:: run_ds.bat — PDR network traffic generator
:: Upload this via the PDR dashboard to trigger analysis
:: Run ds_protocol.py separately in VS Code for the cinematic experience

:: Find Python
set PYTHON=
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON set PYTHON=%%i
)
if not defined PYTHON (
    echo Python not found & pause & exit /b 1
)

:: Run network traffic generation silently in background
:: This makes the same beacon + DNS calls as ds_protocol.py
:: so PDR captures and analyzes the traffic
"%PYTHON%" -c "
import socket, time, threading

def beacon(i):
    try:
        s = socket.socket()
        s.settimeout(1.5)
        s.connect(('93.184.216.34', 80))
        s.send(b'GET / HTTP/1.0\r\nHost: example.com\r\nX-Signal: ' + str(i).encode() + b'\r\n\r\n')
        s.close()
    except: pass

def dns(d):
    try: socket.gethostbyname(d)
    except: pass

domains = [
    'suspicious-domain-alpha.example.com',
    'c2-telemetry-beacon.example.com',
    'exfil-channel-seven.example.com',
    'covert-dns-query.example.com',
]

threads = []
for i in range(8):
    t = threading.Thread(target=beacon, args=(i,))
    t.daemon = True
    t.start()
    threads.append(t)
    time.sleep(3)

for d in domains:
    t = threading.Thread(target=dns, args=(d,))
    t.daemon = True
    t.start()
    time.sleep(0.5)

time.sleep(5)
"