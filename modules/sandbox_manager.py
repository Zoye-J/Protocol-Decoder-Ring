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
import psutil  # Add this to requirements.txt

class SandboxManager:
    """
    Manages the isolated environment for running suspicious applications
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        """
        Initialize the sandbox manager with configuration
        """
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.sandbox_id = self._generate_sandbox_id()
        self.temp_dir = None
        self.process = None
        self.monitoring_thread = None
        self.is_running = False
        self.start_time = None
        self.process_info = {}
        
        self.logger.info(f"🔧 SandboxManager initialized with ID: {self.sandbox_id}")
        
        # Create necessary directories
        os.makedirs("logs", exist_ok=True)
        os.makedirs("output", exist_ok=True)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the sandbox"""
        logger = logging.getLogger(f"SandboxManager.{datetime.now().strftime('%H%M%S')}")
        logger.setLevel(logging.DEBUG)
        
        # Console handler with colors
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Color formatter for console
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
        
        # File handler
        fh = logging.FileHandler(f"logs/sandbox_{self.sandbox_id}.log")
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
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
                    self.logger.info(f"✅ Loaded configuration from {config_path}")
                    return config
            else:
                self.logger.warning(f"⚠️ Config file not found at {config_path}, using defaults")
                return default_config
        except json.JSONDecodeError:
            self.logger.error(f"❌ Invalid JSON in config file, using defaults")
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
            self.logger.info(f"📁 Created isolated directory: {self.temp_dir}")
            
            # Create subdirectories for isolation
            os.makedirs(os.path.join(self.temp_dir, "appdata"), exist_ok=True)
            os.makedirs(os.path.join(self.temp_dir, "temp"), exist_ok=True)
            os.makedirs(os.path.join(self.temp_dir, "logs"), exist_ok=True)
            
            # TODO: Implement network isolation
            # On Windows, we can use Windows Filtering Platform (WFP)
            # For now, we'll log that network isolation is not fully implemented
            if self.config["sandbox"]["network_isolation"]:
                self.logger.info("🌐 Network isolation enabled (basic mode)")
                self._setup_basic_network_isolation()
            
            # Log environment variables for debugging
            self.logger.debug(f"TEMP directory set to: {self.temp_dir}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to create isolated environment: {e}")
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
        
        self.logger.debug("🌐 Basic network isolation configured")
    
    def run_application(self, app_path: str, args: List[str] = None) -> bool:
        """
        Run the suspicious application in the isolated environment
        """
        if not os.path.exists(app_path):
            self.logger.error(f"❌ Application not found: {app_path}")
            return False
        
        try:
            # Prepare environment
            env = os.environ.copy()
            env['TEMP'] = self.temp_dir
            env['TMP'] = self.temp_dir
            
            # Start the application
            self.logger.info(f"🚀 Starting application: {app_path}")
            self.logger.info(f"   Arguments: {args if args else 'None'}")
            self.logger.info(f"   Working directory: {self.temp_dir}")
            
            self.process = subprocess.Popen(
                [app_path] + (args or []),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.temp_dir,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            self.is_running = True
            self.start_time = time.time()
            
            # Get process info
            try:
                proc = psutil.Process(self.process.pid)
                self.process_info = {
                    'pid': self.process.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'create_time': proc.create_time()
                }
                self.logger.info(f"📊 Process info: {self.process_info['name']} (PID: {self.process.pid})")
            except:
                self.process_info = {'pid': self.process.pid}
            
            # Start monitoring in background
            self.monitoring_thread = threading.Thread(
                target=self._monitor_application,
                daemon=True
            )
            self.monitoring_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to run application: {e}")
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
                    self.logger.info(f"✅ Application finished with code: {self.process.returncode}")
                    
                    # Read output
                    stdout, stderr = self.process.communicate(timeout=5)
                    if stdout:
                        self.logger.debug(f"STDOUT: {stdout[:200]}...")
                    if stderr:
                        self.logger.warning(f"STDERR: {stderr[:200]}...")
                    
                    self.is_running = False
                    break
                
                # Monitor resource usage if psutil is available
                try:
                    proc = psutil.Process(self.process.pid)
                    cpu_percent = proc.cpu_percent()
                    memory_info = proc.memory_info()
                    
                    # Check thresholds
                    if cpu_percent > self.config["monitoring"]["cpu_threshold"]:
                        self.logger.warning(f"⚠️ High CPU usage: {cpu_percent}%")
                    
                    if memory_info.rss / (1024 * 1024) > self.config["monitoring"]["memory_threshold"]:
                        self.logger.warning(f"⚠️ High memory usage: {memory_info.rss / (1024 * 1024):.2f} MB")
                        
                except:
                    pass  # psutil not available or process gone
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring thread: {e}")
                break
        
        # Timeout reached
        if self.is_running:
            self.logger.warning(f"⚠️ Application timeout reached ({timeout}s), terminating...")
            self.terminate_application()
    
    def terminate_application(self):
        """Terminate the running application"""
        if self.process and self.is_running:
            try:
                self.logger.info("🛑 Terminating application...")
                
                # Try graceful termination first
                self.process.terminate()
                
                # Wait for it to terminate
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if needed
                    self.logger.warning("⚠️ Force killing application...")
                    self.process.kill()
                    self.process.wait(timeout=2)
                
                self.is_running = False
                self.logger.info("✅ Application terminated")
                
            except Exception as e:
                self.logger.error(f"Error terminating application: {e}")
    
    def get_environment_info(self) -> Dict:
        """Get information about the sandbox environment"""
        return {
            "sandbox_id": self.sandbox_id,
            "temp_directory": self.temp_dir,
            "is_running": self.is_running,
            "process_id": self.process.pid if self.process else None,
            "process_info": self.process_info,
            "runtime_seconds": time.time() - self.start_time if self.start_time else 0,
            "config": self.config
        }
    
    def get_process_output(self) -> Tuple[str, str]:
        """Get stdout and stderr from the process"""
        if self.process and self.process.poll() is not None:
            return self.process.stdout.read(), self.process.stderr.read()
        return "", ""
    
    def cleanup(self):
        """Clean up the sandbox environment"""
        self.logger.info("🧹 Cleaning up sandbox environment...")
        
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
                self.logger.info(f"✅ Removed temporary directory: {self.temp_dir}")
            except Exception as e:
                self.logger.error(f"Failed to remove temp directory: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        self.create_isolated_environment()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()


# Simple test if run directly
if __name__ == "__main__":
    # Add psutil to requirements if not already there
    print("Testing SandboxManager...")
    
    with SandboxManager() as sandbox:
        print(f"Sandbox created: {sandbox.get_environment_info()}")
        
        # Test with calculator (safe app)
        calc_path = "C:\\Windows\\System32\\calc.exe"
        if os.path.exists(calc_path):
            sandbox.run_application(calc_path)
            
            # Keep running for a bit
            print("Running calculator for 5 seconds...")
            time.sleep(5)
        else:
            print("Calculator not found, skipping test")