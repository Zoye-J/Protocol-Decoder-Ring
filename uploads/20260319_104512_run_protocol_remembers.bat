@echo off
:: THE PROTOCOL REMEMBERS — Self-contained PDR Test Sample
:: Single file: bat extracts and runs the embedded Python script

:: Write the Python script to a temp file then run it in a new window
set TMPPY=%TEMP%\pdr_protocol_remembers_%RANDOM%.py

:: Find Python
set PYTHON=
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON set PYTHON=%%i
)
if not defined PYTHON (
    echo Python not found.
    pause
    exit /b 1
)

:: Extract embedded Python to temp file
(
echo import sys, time, socket, threading
echo DIM="\033[2m"; WHITE="\033[97m"; YELLOW="\033[33m"; RED="\033[91m"; CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"
echo def tw^(text, color=WHITE, delay=0.045, nl=True^):
echo     sys.stdout.write^(color^)
echo     [^(sys.stdout.write^(c^), sys.stdout.flush^(^), time.sleep^(delay^)^) for c in text]
echo     sys.stdout.write^(RESET^)
echo     if nl: print^(^)
echo def pause^(s^):
echo     for _ in range^(int^(s*2^)^): sys.stdout.write^(DIM+"."+RESET^); sys.stdout.flush^(^); time.sleep^(0.5^)
echo     print^(^)
echo def divider^(c="─", col=DIM^): print^(col+c*60+RESET^)
echo def phase^(name, col=YELLOW^):
echo     print^(^); divider^("─",DIM^); print^(f"{col}{BOLD}  {name}{RESET}"^); divider^("─",DIM^); print^(^)
echo def beacon^(h,p,msg,n^):
echo     try:
echo         s=socket.socket^(^); s.settimeout^(1.5^); s.connect^(^(h,p^)^)
echo         s.send^(f"GET / HTTP/1.0\r\nHost: {h}\r\nX-Beacon: {n}\r\n\r\n".encode^(^)^); s.close^(^)
echo     except: pass
echo def dns^(d^):
echo     try: socket.gethostbyname^(d^)
echo     except: pass
echo try:
echo     import ctypes; ctypes.windll.kernel32.SetConsoleTitleW^("THE PROTOCOL REMEMBERS"^)
echo except: pass
echo print^(^); print^(DIM+"  "+"="*58+RESET^); print^(^); time.sleep^(0.5^)
echo phase^("PHASE I  ·  ARRIVAL", YELLOW^)
echo for text,color,spd in [^("A foreign signal stirs",WHITE,0.055^),^("An unknown process has awakened",WHITE,0.05^),^("The network feels your presence",WHITE,0.05^),^("Connection established beyond sight",CYAN,0.045^),^("Something listens between packets",CYAN,0.045^)]:
echo     time.sleep^(0.6^); tw^(f"  {text}...",color,spd^)
echo pause^(1.5^)
echo phase^("PHASE II  ·  THE SIGNAL CALLS HOME", YELLOW^)
echo lines=[^("The signal calls home.",0^),^("Heartbeat transmitted into the void.",1^),^("The master awaits telemetry.",2^),^("Whispers travel through hidden ports.",3^),^("Trust has been misplaced.",4^)]
echo for line,i in lines:
echo     time.sleep^(0.8^); tw^(f"  {line}",WHITE,0.048^)
echo     t=threading.Thread^(target=beacon,args=^("93.184.216.34",80,line[:20],i+1^)^); t.daemon=True; t.start^(^)
echo     time.sleep^(0.2^); print^(DIM+f"    › beacon {i+1} transmitted"+RESET^)
echo pause^(2^)
echo phase^("PHASE III  ·  OBSERVATION HAS BEGUN", RED^)
echo p3=[^("Patterns repeat","too perfectly.",WHITE^),^("Entropy rises","above threshold.",WHITE^),^("Your defenses","begin to falter.",YELLOW^),^("Observation","has begun.",YELLOW^),^("You are no longer","unseen.",RED^)]
echo dns_d=["suspicious-domain-alpha.example.com","c2-telemetry-beacon.example.com","exfil-channel-seven.example.com","covert-dns-query.example.com"]
echo for i,^(p1,p2,col^) in enumerate^(p3^):
echo     time.sleep^(0.9^); sys.stdout.write^(f"  {WHITE}{p1}{RESET}"^); sys.stdout.flush^(^); time.sleep^(0.4^)
echo     sys.stdout.write^(f" {col}{BOLD}{p2}{RESET}\n"^); sys.stdout.flush^(^)
echo     if i<len^(dns_d^): t=threading.Thread^(target=dns,args=^(dns_d[i],^)^); t.daemon=True; t.start^(^)
echo pause^(2^)
echo phase^("PHASE IV  ·  THE WATCHER STIRS", RED^)
echo for line in ["The watcher has noticed.","Behavior classified.","Patterns logged.","Signatures extracted.","Analysis complete.","Judgment approaches."]:
echo     time.sleep^(0.7^); sys.stdout.write^(DIM+f"  {line}"+RESET^); sys.stdout.flush^(^); time.sleep^(0.15^); sys.stdout.write^("\r"^); tw^(f"  {line}",RED,0.04^)
echo pause^(1^)
echo print^(^); time.sleep^(1^); divider^("=",RED^); time.sleep^(0.5^)
echo sys.stdout.write^(f"\n  {RED}{BOLD}"^); sys.stdout.flush^(^)
echo for word in ["THE"," ","PROTOCOL"," ","REMEMBERS"]:
echo     [^(sys.stdout.write^(c^),sys.stdout.flush^(^),time.sleep^(0.12^)^) for c in word]; time.sleep^(0.1^)
echo sys.stdout.write^(RESET+"\n"^); sys.stdout.flush^(^)
echo time.sleep^(0.5^); divider^("=",RED^); print^(^); time.sleep^(1.5^)
echo try:
echo     import tkinter as tk; from tkinter import font as tkfont
echo     root=tk.Tk^(^); root.title^("Protocol Decoder Ring"^); root.configure^(bg="#0a0a0a"^); root.resizable^(False,False^)
echo     w,h=640,320; sw=root.winfo_screenwidth^(^); sh=root.winfo_screenheight^(^); root.geometry^(f"{w}x{h}+{^(sw-w^)//2}+{^(sh-h^)//2}"^)
echo     tk.Frame^(root,bg="#cc0000",height=4^).pack^(fill="x"^); tk.Frame^(root,bg="#0a0a0a",height=40^).pack^(^)
echo     try: tf=tkfont.Font^(family="Palatino Linotype",size=38,weight="bold"^); sf=tkfont.Font^(family="Palatino Linotype",size=13,slant="italic"^); bf=tkfont.Font^(family="Palatino Linotype",size=11^)
echo     except: tf=tkfont.Font^(size=38,weight="bold"^); sf=tkfont.Font^(size=13,slant="italic"^); bf=tkfont.Font^(size=11^)
echo     tk.Label^(root,text="THE PROTOCOL REMEMBERS",font=tf,fg="#cc2200",bg="#0a0a0a"^).pack^(^)
echo     tk.Frame^(root,bg="#0a0a0a",height=16^).pack^(^)
echo     tk.Label^(root,text="your traffic has been analyzed",font=sf,fg="#888877",bg="#0a0a0a"^).pack^(^)
echo     tk.Frame^(root,bg="#0a0a0a",height=32^).pack^(^); tk.Frame^(root,bg="#cc0000",height=1^).pack^(fill="x",padx=80^); tk.Frame^(root,bg="#0a0a0a",height=20^).pack^(^)
echo     tk.Button^(root,text="RISE AGAIN",font=bf,fg="#888877",bg="#1a1a1a",activeforeground="#ffffff",activebackground="#2a2a2a",relief="flat",bd=0,padx=24,pady=8,cursor="hand2",command=root.destroy^).pack^(^)
echo     root.mainloop^(^)
echo except: pass
echo print^(^); tw^("  Analysis data transmitted.",DIM,0.03^); tw^("  Protocol Decoder Ring has observed all.",DIM,0.03^); print^(^); time.sleep^(0.5^)
) > "%TMPPY%"

:: Launch visible terminal window running the extracted script
start "THE PROTOCOL REMEMBERS" cmd /k ""%PYTHON%" "%TMPPY%" & del "%TMPPY%" 2>nul"