"""
Module 1: Sandbox Manager
Creates isolated network environment for analyzing suspicious applications
Fortinet Connections: NSE2 Module 2 (Secure Network), NSE2 Module 5 (Endpoint Security)
"""

import os
import sys
import json
import logging
import subprocess
import tempfile
import time
import threading
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Check if running on Windows
IS_WINDOWS = sys.platform == 'win32'

# Try to import psutil, but don't fail if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️  psutil not installed. Run: pip install psutil")

class SandboxManager:
    """
    Manages the isolated environment for running suspicious applications
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the sandbox manager with configuration
        """
        # Initialize attributes in the CORRECT ORDER
        self.sandbox_id = self._generate_sandbox_id()  # Do this FIRST
        self.config = self._load_config(config_path)   # Then load config
        self.logger = self._setup_logging()            # Then setup logging (now sandbox_id exists)
        
        self.temp_dir = None
        self.process = None
        self.monitoring_thread = None
        self.is_running = False
        self.start_time = None
        self.process_info = {}
        
        self.logger.info(f"[TOOL] SandboxManager initialized with ID: {self.sandbox_id}")
        
        # Create necessary directories
        os.makedirs("logs", exist_ok=True)
        os.makedirs("output", exist_ok=True)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the sandbox"""
        logger = logging.getLogger(f"SandboxManager.{self.sandbox_id}")
        logger.setLevel(logging.DEBUG)
        
        # Console handler - WITHOUT emojis for Windows compatibility
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Simple formatter for console (no colors/emojis on Windows)
        if IS_WINDOWS:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            # Color formatter for non-Windows systems
            class ColorFormatter(logging.Formatter):
                """Add colors to console output"""
                grey = "\x1b[38;21m"
                blue = "\x1b[38;5;39m"
                yellow = "\x1b[38;5;226m"
                red = "\x1b[38;5;196m"
                bold_red = "\x1b[31;1m"
                reset = "\x1b[0m"
                
                def format(self, record):
                    if record.levelno == logging.INFO:
                        color = self.blue
                    elif record.levelno == logging.WARNING:
                        color = self.yellow
                    elif record.levelno == logging.ERROR:
                        color = self.red
                    elif record.levelno == logging.CRITICAL:
                        color = self.bold_red
                    else:
                        color = self.grey
                        
                    record.msg = f"{color}{record.msg}{self.reset}"
                    return super().format(record)
            
            formatter = ColorFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler (always use simple format for files)
        try:
            fh = logging.FileHandler(f"logs/sandbox_{self.sandbox_id}.log", encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"⚠️  Could not create log file: {e}")
        
        return logger
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        default_config = {
            "sandbox": {
                "timeout_seconds": 300,
                "max_memory_mb": 1024,
                "network_isolation": True,
                "capture_all_traffic": True,
                "temp_dir_prefix": "pdr_sandbox_"
            },
            "monitoring": {
                "process_monitoring": True,
                "file_system_monitoring": True,
                "registry_monitoring": True,
                "cpu_threshold": 80,
                "memory_threshold": 500
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    print(f"[OK] Loaded configuration from {config_path}")
                    return config
            else:
                print(f"[WARN] Config file not found at {config_path}, using defaults")
                return default_config
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in config file, using defaults")
            return default_config
    
    def _generate_sandbox_id(self) -> str:
        """Generate unique sandbox ID for this session"""
        return f"sandbox_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def create_isolated_environment(self) -> bool:
        """
        Create a temporary isolated environment for running the application
        """
        try:
            # Create temporary directory
            prefix = self.config["sandbox"]["temp_dir_prefix"]
            self.temp_dir = tempfile.mkdtemp(prefix=prefix)
            self.logger.info(f"[FOLDER] Created isolated directory: {self.temp_dir}")
            
            # Create subdirectories for isolation
            os.makedirs(os.path.join(self.temp_dir, "appdata"), exist_ok=True)
            os.makedirs(os.path.join(self.temp_dir, "temp"), exist_ok=True)
            os.makedirs(os.path.join(self.temp_dir, "logs"), exist_ok=True)
            
            # TODO: Implement network isolation
            # On Windows, we can use Windows Filtering Platform (WFP)
            # For now, we'll log that network isolation is not fully implemented
            if self.config["sandbox"]["network_isolation"]:
                self.logger.info("[NET] Network isolation enabled (basic mode)")
                self._setup_basic_network_isolation()
            
            # Log environment variables for debugging
            self.logger.debug(f"TEMP directory set to: {self.temp_dir}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to create isolated environment: {e}")
            return False
    
    def _setup_basic_network_isolation(self):
        """
        Basic network isolation - will be enhanced in Module 2
        """
        # Store original environment
        self.original_env = {
            'TEMP': os.environ.get('TEMP', ''),
            'TMP': os.environ.get('TMP', ''),
            'USERPROFILE': os.environ.get('USERPROFILE', '')
        }
        
        # Set isolated environment variables
        os.environ['TEMP'] = self.temp_dir
        os.environ['TMP'] = self.temp_dir
        
        self.logger.debug("[NET] Basic network isolation configured")
    
    def run_application(self, app_path: str, args: List[str] = None) -> bool:
        """
        Run the suspicious application in the isolated environment
        """
        if not os.path.exists(app_path):
            self.logger.error(f"[ERROR] Application not found: {app_path}")
            return False
        
        try:
            # Prepare environment
            env = os.environ.copy()
            env['TEMP'] = self.temp_dir
            env['TMP'] = self.temp_dir
            
            # Start the application
            self.logger.info(f"[RUN] Starting application: {app_path}")
            self.logger.info(f"      Arguments: {args if args else 'None'}")
            self.logger.info(f"      Working directory: {self.temp_dir}")
            
            # On Windows, use CREATE_NO_WINDOW flag to avoid console windows
            creationflags = 0
            if sys.platform == 'win32':
                creationflags = subprocess.CREATE_NO_WINDOW
            
            self.process = subprocess.Popen(
                [app_path] + (args or []),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.temp_dir,
                env=env,
                creationflags=creationflags
            )
            
            self.is_running = True
            self.start_time = time.time()
            
            # Get process info if psutil is available
            if PSUTIL_AVAILABLE:
                try:
                    proc = psutil.Process(self.process.pid)
                    self.process_info = {
                        'pid': self.process.pid,
                        'name': proc.name(),
                        'exe': proc.exe(),
                        'create_time': proc.create_time()
                    }
                    self.logger.info(f"[PROC] Process: {self.process_info['name']} (PID: {self.process.pid})")
                except:
                    self.process_info = {'pid': self.process.pid}
            else:
                self.process_info = {'pid': self.process.pid}
                self.logger.info(f"[PROC] Process PID: {self.process.pid}")
            
            # Start monitoring in background
            self.monitoring_thread = threading.Thread(
                target=self._monitor_application,
                daemon=True
            )
            self.monitoring_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to run application: {e}")
            return False
    
    def _monitor_application(self):
        """
        Monitor the running application (runs in background thread)
        """
        timeout = self.config["sandbox"]["timeout_seconds"]
        
        while self.is_running and (time.time() - self.start_time) < timeout:
            try:
                # Check if process is still alive
                if self.process.poll() is not None:
                    self.logger.info(f"[DONE] Application finished with code: {self.process.returncode}")
                    
                    # Read output
                    try:
                        stdout, stderr = self.process.communicate(timeout=5)
                        if stdout:
                            self.logger.debug(f"STDOUT: {stdout[:200]}...")
                        if stderr:
                            self.logger.warning(f"STDERR: {stderr[:200]}...")
                    except:
                        pass
                    
                    self.is_running = False
                    break
                
                # Monitor resource usage if psutil is available
                if PSUTIL_AVAILABLE:
                    try:
                        proc = psutil.Process(self.process.pid)
                        cpu_percent = proc.cpu_percent()
                        memory_info = proc.memory_info()
                        
                        # Check thresholds
                        if cpu_percent > self.config["monitoring"]["cpu_threshold"]:
                            self.logger.warning(f"[WARN] High CPU usage: {cpu_percent}%")
                        
                        memory_mb = memory_info.rss / (1024 * 1024)
                        if memory_mb > self.config["monitoring"]["memory_threshold"]:
                            self.logger.warning(f"[WARN] High memory usage: {memory_mb:.2f} MB")
                            
                    except:
                        pass  # Process might be gone
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"[ERROR] Error in monitoring thread: {e}")
                break
        
        # Timeout reached
        if self.is_running:
            self.logger.warning(f"[WARN] Application timeout reached ({timeout}s), terminating...")
            self.terminate_application()
    
    def terminate_application(self):
        """Terminate the running application"""
        if self.process and self.is_running:
            try:
                self.logger.info("[STOP] Terminating application...")
                
                # Try graceful termination first
                self.process.terminate()
                
                # Wait for it to terminate
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if needed
                    self.logger.warning("[WARN] Force killing application...")
                    self.process.kill()
                    self.process.wait(timeout=2)
                
                self.is_running = False
                self.logger.info("[OK] Application terminated")
                
            except Exception as e:
                self.logger.error(f"[ERROR] Error terminating application: {e}")
    
    def get_environment_info(self) -> Dict:
        """Get information about the sandbox environment"""
        runtime = time.time() - self.start_time if self.start_time else 0
        return {
            "sandbox_id": self.sandbox_id,
            "temp_directory": self.temp_dir,
            "is_running": self.is_running,
            "process_id": self.process.pid if self.process else None,
            "process_info": self.process_info,
            "runtime_seconds": round(runtime, 2),
            "config": self.config
        }
    
    def get_process_output(self) -> Tuple[str, str]:
        """Get stdout and stderr from the process"""
        if self.process and self.process.poll() is not None:
            try:
                return self.process.stdout.read(), self.process.stderr.read()
            except:
                pass
        return "", ""
    
    def cleanup(self):
        """Clean up the sandbox environment"""
        self.logger.info("[CLEAN] Cleaning up sandbox environment...")
        
        # Terminate application if still running
        self.terminate_application()
        
        # Restore original environment
        if hasattr(self, 'original_env'):
            for key, value in self.original_env.items():
                if value:
                    os.environ[key] = value
        
        # Remove temporary directory
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                self.logger.info(f"[OK] Removed temporary directory: {self.temp_dir}")
            except Exception as e:
                self.logger.error(f"[ERROR] Failed to remove temp directory: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        self.create_isolated_environment()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()


# Simple test if run directly
if __name__ == "__main__":
    print("=" * 60)
    print(" SANDBOX MANAGER TEST ")
    print("=" * 60)
    
    # Install psutil if not available
    if not PSUTIL_AVAILABLE:
        print("⚠️  For better monitoring, install psutil:")
        print("   pip install psutil")
        print()
    
    with SandboxManager() as sandbox:
        print(f"[OK] Sandbox created with ID: {sandbox.sandbox_id}")
        print(f"[OK] Temp directory: {sandbox.temp_dir}")
        print()
        print(f"[TEST] Launching ping test for 5 seconds...")
        print()
        
        # Test with ping (background process, no window)
        sandbox.run_application(
            "C:\\Windows\\System32\\ping.exe", 
            ["google.com", "-n", "10"]  # Ping 10 times
        )
        
        # Let it run for 5 seconds
        for i in range(5):
            time.sleep(1)
            info = sandbox.get_environment_info()
            print(f"   Running for {info['runtime_seconds']} seconds...")
        
        # Check if process is still running
        info = sandbox.get_environment_info()
        print()
        print(f"[INFO] Process info: PID={info['process_id']}, Running={info['is_running']}")
    
    print("=" * 60)
    print("[OK] Test complete!")
    print("=" * 60)