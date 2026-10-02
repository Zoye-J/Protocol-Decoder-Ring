"""
ds_protocol.py
THE PROTOCOL REMEMBERS — Dark Souls Edition
Run directly: python ds_protocol.py
"""

import sys
import time
import os
import threading

# ── Cinematic color palette ──────────────────────────────────────────────────
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
WHITE = "\033[97m"
GREY  = "\033[90m"
RED   = "\033[91m"
DKRED = "\033[38;5;88m"      # Deep blood red
GOLD  = "\033[38;5;220m"     # Ember gold
AMBER = "\033[38;5;214m"     # Bonfire glow
ASH   = "\033[38;5;243m"     # Hollow grey

# ── Windows console setup ────────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
        k.SetConsoleTitleW("— THE PROTOCOL REMEMBERS —")
    except Exception:
        pass


def typewrite(text, color=WHITE, delay=0.045, nl=True):
    """Cinematic typewriter effect with variable timing"""
    sys.stdout.write("    " + color)
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        d = delay
        if char in ".!?": d = delay * 8
        elif char in ",;:": d = delay * 4
        elif char == " ": d = delay * 0.5
        elif char in "…—": d = delay * 5
        time.sleep(d)
    sys.stdout.write(RESET)
    if nl:
        print()


def pause(s=1.0):
    """Dramatic pause with ellipsis"""
    sys.stdout.write("    " + DIM + ". ")
    sys.stdout.flush()
    time.sleep(0.5)
    sys.stdout.write(". ")
    sys.stdout.flush()
    time.sleep(0.5)
    sys.stdout.write(". ")
    sys.stdout.flush()
    time.sleep(0.5)
    sys.stdout.write(RESET + "\n")
    time.sleep(s)


def fade_in(text, color=RED):
    """Text fades in from darkness"""
    for i in range(1, 5):
        intensity = i * 60
        sys.stdout.write(f"    \033[38;5;{intensity}m{text}\r")
        sys.stdout.flush()
        time.sleep(0.15)
    sys.stdout.write(f"    {color}{BOLD}{text}{RESET}\n")
    sys.stdout.flush()


def ember_glow(text):
    """Text glows like dying embers"""
    colors = [DKRED, RED, GOLD, AMBER, GOLD, RED, DKRED]
    for _ in range(2):
        for c in colors:
            sys.stdout.write(f"    {c}{text}\r")
            sys.stdout.flush()
            time.sleep(0.08)
    sys.stdout.write(f"    {DKRED}{BOLD}{text}{RESET}\n")
    sys.stdout.flush()


def bonfire_flicker(text):
    """Flickering like a bonfire flame"""
    for _ in range(4):
        sys.stdout.write(f"    {AMBER}{text}\r")
        sys.stdout.flush()
        time.sleep(0.05)
        sys.stdout.write(f"    {GOLD}{text}\r")
        sys.stdout.flush()
        time.sleep(0.05)
        sys.stdout.write(f"    {RED}{text}\r")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"    {DKRED}{BOLD}{text}{RESET}\n")
    sys.stdout.flush()


def die(text):
    """Text dies slowly"""
    sys.stdout.write(f"    {BOLD}{text}\n")
    sys.stdout.flush()
    time.sleep(1.0)
    for i in range(10, 0, -1):
        sys.stdout.write(f"    \033[38;5;{232+i*2}m{text}\r")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("    " + " " * len(text) + "\r")
    sys.stdout.flush()


def blank(n=1):
    for _ in range(n):
        print()


def sleep(s):
    time.sleep(s)


# ── Dark Souls Popup ─────────────────────────────────────────────────────────
def show_you_were_observed():
    """Cinematic Dark Souls-style death message - runs in separate thread"""
    # Don't create window immediately - wait for the right moment
    time.sleep(2.0)  # Wait for console to finish
    
    try:
        import tkinter as tk
        from tkinter import font as tkfont
        
        root = tk.Tk()
        root.title("")
        root.configure(bg="black")
        root.overrideredirect(True)  # No window decorations
        root.attributes("-topmost", True)
        root.attributes("-alpha", 0.0)
        
        # Get screen dimensions
        W, H = 900, 400
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
        
        # Dark Souls font
        try:
            title_font = tkfont.Font(family="Palatino Linotype", size=48, weight="bold")
            subtitle_font = tkfont.Font(family="Palatino Linotype", size=16, weight="normal")
        except:
            title_font = tkfont.Font(size=48, weight="bold")
            subtitle_font = tkfont.Font(size=16)
        
        # Create dark background
        bg_frame = tk.Frame(root, bg="black")
        bg_frame.pack(fill="both", expand=True)
        
        # Blood line at top
        tk.Frame(bg_frame, bg="#400000", height=2).pack(fill="x", padx=100, pady=(80, 0))
        
        # Main title - "YOU WERE OBSERVED"
        title_label = tk.Label(
            bg_frame,
            text="YOU WERE OBSERVED",
            font=title_font,
            fg="#8b0000",
            bg="black"
        )
        title_label.pack(pady=(40, 10))
        
        
        # Blood line at bottom
        tk.Frame(bg_frame, bg="#400000", height=2).pack(fill="x", padx=150, pady=(40, 80))
        
        # Fade in animation
        def fade_in_out():
            # Fade in
            alpha = 0.0
            while alpha < 1.0:
                alpha += 0.02
                root.attributes("-alpha", alpha)
                root.update()
                time.sleep(0.02)
            
            # Stay visible
            time.sleep(2.5)
            
            # Fade out
            alpha = 1.0
            while alpha > 0.0:
                alpha -= 0.03
                root.attributes("-alpha", alpha)
                root.update()
                time.sleep(0.02)
            
            root.destroy()
        
        # Start fade animation after window is created
        root.after(100, fade_in_out)
        root.mainloop()
        
    except ImportError:
        # Fallback for systems without tkinter
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                "YOU WERE OBSERVED\n\nprotocol heir",
                "THE PROTOCOL REMEMBERS",
                0x00000010  # MB_ICONSTOP
            )
        except Exception:
            pass


# ── Cinematic Script ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    
    # Clear screen
    os.system("cls" if sys.platform == "win32" else "clear")
    
    # ── Opening ─────────────────────────────────────────────────────────────
    blank(5)
    pause(0.5)
    sleep(1.5)
    typewrite("The quiet has been disturbed..", GREY, 0.06)
    sleep(2.0)
    
    blank()
    
    # ── PHASE I: ARRIVAL ────────────────────────────────────────────────────
    typewrite("An observer awakens beyond the glass.", WHITE, 0.05)
    sleep(1.2)
    typewrite("You were not meant to witness this...", WHITE, 0.05)
    sleep(1.2)
    
    blank()
    
    typewrite("The unseen now turns its gaze toward you....", DKRED, 0.06)
    sleep(0.8)
    
    blank(2)
    pause(0.5)
    
    # ── PHASE II: THE BEACON ────────────────────────────────────────────────
    typewrite("Your defenses were only a suggestion.", WHITE, 0.05)
    sleep(1.0)
    typewrite("Heartbeat transmitted into the void.", WHITE, 0.05)
    sleep(1.0)
    
    blank()
    
  
    
    # ── PHASE III: DISCOVERY ────────────────────────────────────────────────
    typewrite("The cycle resumes...", WHITE, 0.06)
    sleep(0.8)
    typewrite("...too perfectly.", DKRED, 0.08)
    sleep(1.2)
    
    blank()
    
    ember_glow("Your defenses begin to falter.")
    sleep(1.0)
    typewrite("Observation has begun...", WHITE, 0.07)
    sleep(1.0)
    
    blank()
    
    fade_in("You are no longer unseen.", DKRED)
    sleep(2.0)
    
    blank(2)
    
    # ── PHASE IV: JUDGMENT ──────────────────────────────────────────────────
    bonfire_flicker("The watcher has noticed.")
    sleep(1.2)
    
    blank()
    
    
    typewrite("Judgment...", WHITE, 0.09)
    sleep(0.8)
    typewrite("...approaches.", DKRED, 0.1)
    sleep(2.5)
    
    blank(3)
    sleep(0.5)
    
    # ── DARK SOULS POPUP ─────────────────────────────────────────────────────
    # Now show the popup - it will appear after the console text completes
    show_you_were_observed()
    
    # ── EPILOGUE ─────────────────────────────────────────────────────────────
    # These will run after popup closes
    blank(2)
    die("the watcher sleeps now")
    sleep(1.0)
    typewrite("until the next signal stirs...", ASH, 0.07)
    blank(3)
    sleep(1.0)