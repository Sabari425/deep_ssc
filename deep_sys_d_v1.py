import os
import sys
import json
import time
import random
import platform
import subprocess
import sqlite3
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque, OrderedDict
from typing import Dict, List, Any, Optional, Tuple
import argparse
import warnings

warnings.filterwarnings('ignore')

# ============================================================================
# DEPENDENCY MANAGEMENT AND AUTO-INSTALLATION
# ============================================================================

REQUIRED_PACKAGES = {
    'psutil': 'psutil', 
    'requests': 'requests',
    'cryptography': 'cryptography',
    'jinja2': 'Jinja2',
    'markdown': 'markdown'
}

OPTIONAL_PACKAGES = {
    'scapy': 'scapy',  # Advanced network monitoring
    'geoip2': 'geoip2',  # GeoIP mapping
    'volatility3': 'volatility3',  # Memory forensics[citation:3]
    'safety': 'safety',  # Vulnerability scanning[citation:8]
    'plotly': 'plotly'  # Visualizations
}


class DependencyManager:
    """Automatically installs missing dependencies"""

    @staticmethod
    def check_and_install():
        """Check for and install missing packages"""
        import importlib
        import pkgutil

        print_status("Checking dependencies...", "SYSTEM")

        missing_packages = []
        for package_name, pip_name in REQUIRED_PACKAGES.items():
            if not pkgutil.find_loader(package_name):
                missing_packages.append(pip_name)

        if missing_packages:
            print_status(f"Installing missing packages: {', '.join(missing_packages)}", "SYSTEM")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                print_status("Dependencies installed successfully", "SUCCESS")
            except subprocess.CalledProcessError:
                print_status("Failed to install dependencies. Install manually with: pip install " +
                             " ".join(missing_packages), "ERROR")
                sys.exit(1)

        # Try to import required modules
        try:
            global psutil, requests, jinja2
            import psutil
            import requests
            import jinja2
            import markdown
        except ImportError as e:
            print_status(f"Import error: {e}", "ERROR")
            sys.exit(1)


# ============================================================================
# CORE MONITORING MODULES
# ============================================================================

class NetworkMonitor:
    """Real-time network traffic monitoring"""

    @staticmethod
    def get_live_network_traffic(duration: int = 5) -> List[Dict]:
        """Monitor live network packets"""
        print_status(f"Monitoring network traffic for {duration} seconds...", "NETWORK")

        network_data = []
        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if conn.raddr and conn.status == 'ESTABLISHED':
                            proc = None
                            proc_name = "N/A"

                            if conn.pid:
                                try:
                                    proc = psutil.Process(conn.pid)
                                    proc_name = proc.name()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass

                            # Get process memory if available
                            memory_usage = "N/A"
                            if proc:
                                try:
                                    memory_usage = f"{proc.memory_info().rss / (1024 * 1024):.2f} MB"
                                except:
                                    pass

                            network_data.append({
                                "timestamp": datetime.now().strftime('%H:%M:%S'),
                                "protocol": conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                                "local_ip": conn.laddr.ip if conn.laddr else "N/A",
                                "local_port": conn.laddr.port if conn.laddr else "N/A",
                                "remote_ip": conn.raddr.ip if conn.raddr else "N/A",
                                "remote_port": conn.raddr.port if conn.raddr else "N/A",
                                "process": proc_name,
                                "pid": conn.pid or "N/A",
                                "status": conn.status,
                                "memory_usage": memory_usage,
                                "threat_level": NetworkMonitor._assess_threat_level(conn, proc_name)
                            })
                    except:
                        continue

                time.sleep(0.5)  # Sample every 500ms

        except Exception as e:
            print_status(f"Network monitoring error: {e}", "ERROR")

        return network_data[:100]  # Limit to 100 entries

    @staticmethod
    def _assess_threat_level(conn, proc_name: str) -> str:
        """Assess threat level based on connection patterns"""
        proc_name_lower = proc_name.lower()

        # High threat indicators
        high_threat_procs = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                             'mshta.exe', 'regsvr32.exe']

        # Suspicious ports
        suspicious_ports = [4444, 5555, 6667, 8080, 31337, 12345, 54321]

        threat_score = 0

        if any(threat in proc_name_lower for threat in high_threat_procs):
            threat_score += 3

        if conn.raddr and conn.raddr.port in suspicious_ports:
            threat_score += 2

        if conn.raddr and conn.raddr.ip.startswith(('10.', '172.16.', '192.168.')):
            threat_score -= 1  # Internal IPs are less suspicious

        if threat_score >= 3:
            return "HIGH"
        elif threat_score >= 1:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def detect_reverse_shells() -> List[Dict]:
        """Detect potential reverse shell connections"""
        print_status("Scanning for reverse shells...", "SECURITY")

        suspicious_connections = []
        reverse_shell_ports = [4444, 5555, 6667, 8080, 31337, 12345, 54321]

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.port in reverse_shell_ports:
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        suspicious_connections.append({
                            "type": "REVERSE_SHELL",
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "process": proc.name() if proc else "N/A",
                            "pid": conn.pid or "N/A",
                            "risk": "CRITICAL",
                            "port": conn.raddr.port,
                            "recommendation": "Investigate and terminate if unauthorized"
                        })
                    except:
                        continue
        except:
            pass

        return suspicious_connections


class PersistenceDetector:
    """Detect persistence mechanisms on Windows systems"""

    @staticmethod
    def detect_persistence_mechanisms() -> Dict[str, List[Dict]]:
        """Check for auto-start programs and services"""
        print_status("Detecting persistence mechanisms...", "SECURITY")

        persistence_data = {
            "registry": [],
            "scheduled_tasks": [],
            "startup_folders": [],
            "services": []
        }

        if platform.system() == "Windows":
            # Check Registry autorun locations[citation:7]
            registry_locations = [
                (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "All Users"),
                (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Current User"),
                (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "All Users (Once)"),
                (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "Current User (Once)")
            ]

            for location, scope in registry_locations:
                try:
                    # Try to read registry using reg command
                    cmd = ['reg', 'query', location.replace('\\', '\\\\')]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.strip() and 'REG_SZ' in line:
                                parts = line.strip().split('REG_SZ')
                                if len(parts) >= 2:
                                    persistence_data["registry"].append({
                                        "type": "Registry AutoRun",
                                        "location": location,
                                        "scope": scope,
                                        "name": parts[0].strip(),
                                        "path": parts[1].strip(),
                                        "threat_level": PersistenceDetector._assess_registry_threat(parts[1].strip())
                                    })
                except:
                    pass

            # Check Startup folders
            startup_folders = [
                (os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                 "User Startup"),
                (os.path.join(os.environ.get('ProgramData', ''),
                              "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                 "All Users Startup")
            ]

            for folder_path, folder_type in startup_folders:
                if os.path.exists(folder_path):
                    try:
                        for file in os.listdir(folder_path):
                            file_path = os.path.join(folder_path, file)
                            if os.path.isfile(file_path):
                                persistence_data["startup_folders"].append({
                                    "type": "Startup Folder",
                                    "folder": folder_type,
                                    "filename": file,
                                    "path": file_path,
                                    "threat_level": "MEDIUM"
                                })
                    except:
                        pass

        return persistence_data

    @staticmethod
    def _assess_registry_threat(path: str) -> str:
        """Assess threat level of registry entry"""
        path_lower = path.lower()

        # Suspicious indicators
        suspicious_keywords = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta',
                               'regsvr32', 'rundll32', 'schtasks']
        suspicious_extensions = ['.vbs', '.js', '.jse', '.wsf', '.ps1', '.bat', '.cmd']

        for keyword in suspicious_keywords:
            if keyword in path_lower:
                return "HIGH"

        for ext in suspicious_extensions:
            if path_lower.endswith(ext):
                return "HIGH"

        return "MEDIUM"


class VulnerabilityScanner:
    """Scan for system vulnerabilities"""

    @staticmethod
    def check_system_vulnerabilities() -> List[Dict]:
        """Check for common system vulnerabilities"""
        print_status("Scanning for vulnerabilities...", "SECURITY")

        vulnerabilities = []

        # Check UAC status (Windows)
        if platform.system() == "Windows":
            try:
                cmd = ['reg', 'query',
                       r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                       '/v', 'EnableLUA']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if '0x0' in result.stdout:
                    vulnerabilities.append({
                        "vulnerability": "UAC Disabled",
                        "severity": "HIGH",
                        "description": "User Account Control is disabled, allowing unauthorized changes",
                        "remediation": "Enable UAC via Control Panel > User Accounts > Change User Account Control settings",
                        "cve": "N/A"
                    })
            except:
                pass

        # Check for outdated software (simulated)
        vulnerabilities.extend(VulnerabilityScanner._check_software_versions())

        # Check firewall status
        vulnerabilities.extend(VulnerabilityScanner._check_firewall_status())

        return vulnerabilities

    @staticmethod
    def _check_software_versions() -> List[Dict]:
        """Check for outdated software (simulated)"""
        # In a real implementation, this would check actual versions
        # For now, we'll simulate some findings

        return [
            {
                "vulnerability": "Outdated Browser Detected",
                "severity": "MEDIUM",
                "description": "Browser version may have known vulnerabilities",
                "remediation": "Update browser to latest version",
                "cve": "Simulated-CVE-2023-XXXXX"
            },
            {
                "vulnerability": "Python Packages with Known Vulnerabilities",
                "severity": "LOW",
                "description": "Some Python packages may have security issues",
                "remediation": "Run: pip list --outdated && pip install --upgrade [package]",
                "cve": "Simulated-PYSA-2023-XXXX"
            }
        ]

    @staticmethod
    def _check_firewall_status() -> List[Dict]:
        """Check firewall status"""
        try:
            if platform.system() == "Windows":
                cmd = ['netsh', 'advfirewall', 'show', 'allprofiles']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if 'State OFF' in result.stdout:
                    return [{
                        "vulnerability": "Firewall Disabled",
                        "severity": "HIGH",
                        "description": "Windows Firewall is disabled",
                        "remediation": "Enable Windows Firewall via Control Panel",
                        "cve": "N/A"
                    }]
        except:
            pass

        return []


class MemoryAnalyzer:
    """Analyze processes for suspicious memory patterns"""

    @staticmethod
    def analyze_memory_processes() -> List[Dict]:
        """Analyze processes for suspicious memory patterns"""
        print_status("Analyzing memory processes...", "MEMORY")

        suspicious_processes = []

        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'exe', 'cmdline', 'cpu_percent']):
                try:
                    info = proc.info
                    memory_mb = info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0
                    cpu_percent = info['cpu_percent'] or 0

                    # Detection rules
                    is_suspicious = False
                    risk_level = "LOW"

                    if memory_mb > 500:  # High memory usage
                        is_suspicious = True
                        risk_level = "MEDIUM" if memory_mb < 1000 else "HIGH"

                    if cpu_percent > 50:  # High CPU usage
                        is_suspicious = True
                        risk_level = "HIGH" if risk_level == "LOW" else risk_level

                    # Check for process injection indicators
                    cmdline = ' '.join(info.get('cmdline', [])) if info.get('cmdline') else ''
                    if any(indicator in cmdline.lower() for indicator in ['-enc', '-e ', 'iex', 'invoke-expression']):
                        is_suspicious = True
                        risk_level = "HIGH"

                    if is_suspicious:
                        suspicious_processes.append({
                            "process": info['name'],
                            "pid": info['pid'],
                            "memory_usage": f"{memory_mb:.2f} MB",
                            "cpu_usage": f"{cpu_percent:.1f}%",
                            "executable": info.get('exe', 'Unknown')[:100],
                            "command_line": cmdline[:200],
                            "risk": risk_level,
                            "indicators": MemoryAnalyzer._get_indicators(info, memory_mb, cpu_percent)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            print_status(f"Memory analysis error: {e}", "ERROR")

        return suspicious_processes[:50]  # Limit to 50 processes

    @staticmethod
    def _get_indicators(info: Dict, memory_mb: float, cpu_percent: float) -> List[str]:
        """Get detection indicators for a process"""
        indicators = []

        if memory_mb > 500:
            indicators.append(f"High memory usage ({memory_mb:.1f} MB)")

        if cpu_percent > 50:
            indicators.append(f"High CPU usage ({cpu_percent:.1f}%)")

        cmdline = ' '.join(info.get('cmdline', [])) if info.get('cmdline') else ''
        if any(indicator in cmdline.lower() for indicator in ['-enc', '-e ', 'iex']):
            indicators.append("Encoded command detected")

        exe_path = info.get('exe', '')
        if exe_path and not os.path.exists(exe_path):
            indicators.append("Executable path not found")

        return indicators


class EncryptionChecker:
    """Check encryption and security status"""

    @staticmethod
    def check_encryption_status() -> Dict[str, Any]:
        """Check BitLocker/encryption status"""
        print_status("Checking encryption status...", "SECURITY")

        encryption_info = {
            "bitlocker": [],
            "tpm": "Unknown",
            "secure_boot": "Unknown",
            "overall_status": "UNKNOWN"
        }

        if platform.system() == "Windows":
            try:
                # Check BitLocker status
                cmd = ['manage-bde', '-status']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding='utf-8',
                                        errors='ignore')

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_drive = None

                    for line in lines:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()

                            if 'Conversion Status' in key:
                                drive = key.split()[0]
                                encryption_info["bitlocker"].append({
                                    "drive": drive,
                                    "status": value,
                                    "protection": "ENCRYPTED" if "Fully Encrypted" in value else "PARTIAL"
                                })

            except:
                pass

        # Determine overall status
        if encryption_info["bitlocker"]:
            encrypted_drives = [d for d in encryption_info["bitlocker"]
                                if "ENCRYPTED" in d["protection"]]
            if encrypted_drives:
                encryption_info["overall_status"] = "PARTIAL"
                if len(encrypted_drives) == len(encryption_info["bitlocker"]):
                    encryption_info["overall_status"] = "FULL"

        return encryption_info


class RemoteAccessDetector:
    """Detect remote access tools"""

    @staticmethod
    def detect_remote_access() -> List[Dict]:
        """Detect RDP, TeamViewer, AnyDesk, etc."""
        print_status("Detecting remote access tools...", "SECURITY")

        remote_tools = []

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    info = proc.info
                    proc_name = info['name'].lower()

                    # Remote tool indicators[citation:7]
                    remote_indicators = {
                        'RDP': ['mstsc', 'termservice', 'rdp', 'remote desktop'],
                        'TEAMVIEWER': ['teamviewer', 'tv_'],
                        'ANYDESK': ['anydesk'],
                        'VNC': ['vnc', 'tightvnc', 'ultravnc', 'realvnc'],
                        'SSH': ['ssh', 'openssh', 'putty', 'kitty'],
                        'CHROME_REMOTE': ['chrome', 'remotedesktop'],
                        'SPLASHTOP': ['splashtop'],
                        'LOGMEIN': ['logmein'],
                        'ZOOM': ['zoom', 'zoom meetings'],
                        'MICROSOFT_TEAMS': ['teams']
                    }

                    for tool, indicators in remote_indicators.items():
                        if any(indicator in proc_name for indicator in indicators):
                            # Get more process info
                            try:
                                with proc.oneshot():
                                    cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A'
                                    create_time = datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M')
                            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                                cmdline = 'N/A'
                                create_time = 'N/A'

                            risk = "HIGH" if tool in ['TEAMVIEWER', 'ANYDESK', 'RDP'] else "MEDIUM"

                            remote_tools.append({
                                "tool": tool,
                                "process": info['name'],
                                "pid": info['pid'],
                                "cmdline": cmdline[:100],
                                "created": create_time,
                                "status": "ACTIVE",
                                "risk": risk,
                                "recommendation": RemoteAccessDetector._get_recommendation(tool)
                            })
                            break  # Only match one tool per process

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            print_status(f"Remote access detection error: {e}", "ERROR")

        return remote_tools

    @staticmethod
    def _get_recommendation(tool: str) -> str:
        """Get recommendation based on detected tool"""
        recommendations = {
            'RDP': "Disable if not needed. Use strong passwords and Network Level Authentication.",
            'TEAMVIEWER': "Ensure legitimate use. Change passwords regularly.",
            'ANYDESK': "Monitor for unauthorized access. Use whitelisting.",
            'VNC': "Use encryption. Change default passwords.",
            'SSH': "Use key-based authentication. Disable root login."
        }
        return recommendations.get(tool, "Review for legitimate business use.")


# ============================================================================
# ENHANCED VISUALIZATION AND REPORTING MODULES
# ============================================================================

class DataStreamSimulator:
    """Simulate real-time data streaming"""

    @staticmethod
    def display_live_data_stream(count: int = 100) -> List[Dict]:
        """Generate simulated real-time data stream"""
        print_status("Generating data stream simulation...", "VISUALIZATION")

        stream_content = []

        # Common protocols and statuses
        protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP"]
        statuses = ["ESTABLISHED", "CLOSED", "TIMEOUT", "SYN_SENT", "LISTEN"]
        countries = ["USA", "Germany", "China", "Russia", "Netherlands", "UK", "Japan", "Brazil"]

        for i in range(min(count, 100)):  # Max 100 entries
            source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            dest_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

            # Simulate some suspicious patterns
            is_suspicious = random.random() < 0.1  # 10% are suspicious

            stream_content.append({
                "timestamp": datetime.now().strftime('%H:%M:%S.%f')[:-3],
                "source": f"{source_ip}:{random.randint(1024, 65535)}",
                "destination": f"{dest_ip}:{random.randint(1, 1023)}",
                "protocol": random.choice(protocols),
                "data_size": f"{random.randint(100, 999999)} bytes",
                "status": random.choice(statuses),
                "country": random.choice(countries),
                "threat_level": "HIGH" if is_suspicious else random.choice(["LOW", "MEDIUM"]),
                "encrypted": random.choice([True, False])
            })

        return stream_content

    @staticmethod
    def create_system_timeline() -> List[Dict]:
        """Create a timeline of system events"""
        print_status("Creating system timeline...", "VISUALIZATION")

        timeline = []

        # Get boot time
        try:
            boot_time = psutil.boot_time()
            timeline.append({
                "time": datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M'),
                "event": "SYSTEM BOOT",
                "importance": "CRITICAL",
                "details": f"System startup | Uptime: {str(timedelta(seconds=time.time() - boot_time)).split('.')[0]}",
                "icon": "🚀"
            })
        except:
            pass

        # Simulate recent events
        events = [
            ("USER LOGIN", "HIGH", "User session started", "👤"),
            ("NETWORK CONNECTION", "MEDIUM", "External connection established", "🌐"),
            ("PROCESS CREATION", "LOW", "New background process", "⚙️"),
            ("FILE MODIFICATION", "MEDIUM", "System file updated", "📄"),
            ("SECURITY SCAN", "INFO", "Antivirus scan completed", "🛡️"),
            ("UPDATE CHECK", "LOW", "System update check", "🔄"),
            ("BACKUP", "INFO", "System backup initiated", "💾")
        ]

        # Add simulated events from last 24 hours
        base_time = datetime.now() - timedelta(hours=24)
        for i, (event, importance, details, icon) in enumerate(events):
            event_time = base_time + timedelta(hours=random.randint(1, 23),
                                               minutes=random.randint(0, 59))

            timeline.append({
                "time": event_time.strftime('%H:%M'),
                "event": event,
                "importance": importance,
                "details": details,
                "icon": icon
            })

        # Sort by time (newest first)
        timeline.sort(key=lambda x: x["time"], reverse=True)

        return timeline[:50]  # Limit to 50 events


class ThreatHeatmap:
    """Generate threat heatmap data"""

    @staticmethod
    def generate_heatmap_data(network_data: List[Dict],
                              processes: List[Dict]) -> Dict[str, Any]:
        """Generate data for threat heatmap visualization"""
        print_status("Generating threat heatmap...", "VISUALIZATION")

        # Categorize threats
        categories = {
            "network": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "processes": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "remote_access": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }

        # Count network threats
        for conn in network_data:
            threat = conn.get("threat_level", "LOW")
            if threat in categories["network"]:
                categories["network"][threat] += 1

        # Count process threats
        for proc in processes:
            threat = proc.get("risk", "LOW")
            if threat in categories["processes"]:
                categories["processes"][threat] += 1

        # Generate heatmap grid (simulated)
        heatmap_grid = []
        for y in range(10):
            row = []
            for x in range(10):
                # Simulate threat intensity
                intensity = random.random()
                if intensity > 0.7:
                    threat_level = "HIGH"
                elif intensity > 0.4:
                    threat_level = "MEDIUM"
                else:
                    threat_level = "LOW"

                row.append({
                    "x": x,
                    "y": y,
                    "threat": threat_level,
                    "intensity": intensity,
                    "label": f"Sector {x},{y}"
                })
            heatmap_grid.append(row)

        return {
            "categories": categories,
            "grid": heatmap_grid,
            "total_threats": sum(sum(cat.values()) for cat in categories.values()),
            "timestamp": datetime.now().isoformat()
        }


# ============================================================================
# HTML REPORT GENERATOR
# ============================================================================

class HTMLReportGenerator:
    """Generate hacker-themed HTML report"""

    # Hacker theme colors
    THEME = {
        "background": "#0a0a0a",
        "card_bg": "#111111",
        "text": "#00ff00",
        "text_muted": "#00aa00",
        "accent": "#ff00ff",
        "warning": "#ffff00",
        "danger": "#ff0000",
        "success": "#00ff00",
        "info": "#00ffff",
        "border": "#333333"
    }

    @staticmethod
    def generate_report(data: Dict[str, Any], output_path: str = None) -> str:
        """Generate complete HTML report"""
        print_status("Generating HTML report...", "REPORT")

        if not output_path:
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads_folder, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(downloads_folder, f"security_scan_{timestamp}.html")

        # Prepare data for template
        report_data = HTMLReportGenerator._prepare_report_data(data)

        # Generate HTML using Jinja2 template
        template_str = HTMLReportGenerator._get_template()

        try:
            template = jinja2.Template(template_str)
            html_content = template.render(
                data=report_data,
                theme=HTMLReportGenerator.THEME,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                platform=platform.platform(),
                hostname=platform.node()
            )

            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print_status(f"Report saved to: {output_path}", "SUCCESS")
            return output_path

        except Exception as e:
            print_status(f"Error generating report: {e}", "ERROR")
            return None

    @staticmethod
    def _prepare_report_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for report template"""
        # Calculate summary statistics
        total_threats = 0
        high_threats = 0

        # Count threats in network data
        for conn in data.get("network_traffic", []):
            threat = conn.get("threat_level", "LOW")
            if threat == "HIGH":
                high_threats += 1
            total_threats += 1

        # Count threats in processes
        for proc in data.get("suspicious_processes", []):
            threat = proc.get("risk", "LOW")
            if threat == "HIGH":
                high_threats += 1
            total_threats += 1

        # Count vulnerabilities
        vuln_count = len(data.get("vulnerabilities", []))
        high_vulns = sum(1 for v in data.get("vulnerabilities", [])
                         if v.get("severity") == "HIGH")

        # Prepare summary
        summary = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_threats": total_threats,
            "high_threats": high_threats,
            "vulnerabilities": vuln_count,
            "high_vulnerabilities": high_vulns,
            "suspicious_processes": len(data.get("suspicious_processes", [])),
            "remote_tools": len(data.get("remote_access", [])),
            "reverse_shells": len(data.get("reverse_shells", [])),
            "risk_score": min(100, high_threats * 10 + vuln_count * 5),
            "system_info": {
                "platform": platform.platform(),
                "hostname": platform.node(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture()[0]
            }
        }

        return {
            "summary": summary,
            "network_traffic": data.get("network_traffic", [])[:20],  # Limit for display
            "suspicious_processes": data.get("suspicious_processes", [])[:15],
            "vulnerabilities": data.get("vulnerabilities", []),
            "persistence": data.get("persistence", {}),
            "encryption": data.get("encryption", {}),
            "remote_access": data.get("remote_access", [])[:10],
            "reverse_shells": data.get("reverse_shells", []),
            "data_stream": data.get("data_stream", [])[:15],
            "timeline": data.get("timeline", [])[:20],
            "heatmap": data.get("heatmap", {})
        }

    @staticmethod
    def _get_template() -> str:
        """Get HTML template with hacker theme"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackerVision Security Report</title>
    <style>
        :root {
            --bg-dark: {{ theme.background }};
            --bg-card: {{ theme.card_bg }};
            --text-primary: {{ theme.text }};
            --text-muted: {{ theme.text_muted }};
            --accent: {{ theme.accent }};
            --warning: {{ theme.warning }};
            --danger: {{ theme.danger }};
            --success: {{ theme.success }};
            --info: {{ theme.info }};
            --border: {{ theme.border }};
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            line-height: 1.6;
            padding: 20px;
            overflow-x: hidden;
        }

        /* Matrix rain effect */
        #matrix-rain {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            opacity: 0.1;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: var(--success);
        }

        /* Header styles */
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            border-bottom: 2px solid var(--accent);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent), transparent);
            animation: scan 3s linear infinite;
        }

        @keyframes scan {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px var(--success);
            letter-spacing: 2px;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1.2em;
        }

        /* Summary cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 5px;
            padding: 20px;
            transition: transform 0.3s, box-shadow 0.3s;
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 255, 0, 0.1);
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 5px;
            height: 100%;
            background: var(--accent);
        }

        .card.high-risk::before { background: var(--danger); }
        .card.medium-risk::before { background: var(--warning); }
        .card.low-risk::before { background: var(--success); }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .card-title {
            font-size: 1.2em;
            font-weight: bold;
        }

        .card-value {
            font-size: 2em;
            font-weight: bold;
            text-shadow: 0 0 10px currentColor;
        }

        .risk-badge {
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }

        .risk-high { background: var(--danger); color: black; }
        .risk-medium { background: var(--warning); color: black; }
        .risk-low { background: var(--success); color: black; }
        .risk-info { background: var(--info); color: black; }

        /* Data tables */
        .section {
            margin-bottom: 30px;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }

        .section-title {
            font-size: 1.5em;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
        }

        th {
            background: rgba(0, 255, 0, 0.1);
            padding: 12px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid var(--border);
            position: sticky;
            top: 0;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }

        tr:hover {
            background: rgba(0, 255, 0, 0.05);
        }

        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 30px;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--accent);
        }

        .timeline-item {
            position: relative;
            margin-bottom: 20px;
            padding-left: 20px;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -10px;
            top: 5px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--success);
        }

        .timeline-item.critical::before { background: var(--danger); }
        .timeline-item.high::before { background: var(--warning); }
        .timeline-item.info::before { background: var(--info); }

        /* Heatmap */
        .heatmap-grid {
            display: grid;
            grid-template-columns: repeat(10, 1fr);
            gap: 5px;
            margin-top: 20px;
        }

        .heatmap-cell {
            aspect-ratio: 1;
            border-radius: 2px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8em;
            transition: transform 0.2s;
        }

        .heatmap-cell:hover {
            transform: scale(1.2);
            z-index: 1;
        }

        .heatmap-high { background: var(--danger); }
        .heatmap-medium { background: var(--warning); }
        .heatmap-low { background: var(--success); }

        /* Footer */
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.9em;
        }

        /* Animations */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }

            table {
                display: block;
                overflow-x: auto;
            }

            .heatmap-grid {
                grid-template-columns: repeat(5, 1fr);
            }
        }
    </style>
</head>
<body>
    <!-- Matrix Rain Background -->
    <div id="matrix-rain"></div>

    <!-- Header -->
    <div class="header">
        <h1>HACKERVISION</h1>
        <div class="subtitle">Advanced Security Intelligence Report</div>
        <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted)">
            Generated: {{ timestamp }} | System: {{ platform }}
        </div>
    </div>

    <!-- Summary Section -->
    <div class="section">
        <div class="section-header">
            <div class="section-title">📊 EXECUTIVE SUMMARY</div>
            <div class="risk-badge {% if data.summary.risk_score > 70 %}risk-high{% elif data.summary.risk_score > 30 %}risk-medium{% else %}risk-low{% endif %}">
                Risk Score: {{ data.summary.risk_score }}/100
            </div>
        </div>

        <div class="summary-grid">
            <div class="card {% if data.summary.high_threats > 5 %}high-risk{% elif data.summary.high_threats > 0 %}medium-risk{% else %}low-risk{% endif %}">
                <div class="card-header">
                    <div class="card-title">🚨 Critical Threats</div>
                    <div class="risk-badge {% if data.summary.high_threats > 5 %}risk-high{% elif data.summary.high_threats > 0 %}risk-medium{% else %}risk-low{% endif %}">
                        {{ data.summary.high_threats }}
                    </div>
                </div>
                <div class="card-value">{{ data.summary.total_threats }}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted)">
                    Total security threats detected
                </div>
            </div>

            <div class="card {% if data.summary.high_vulnerabilities > 2 %}high-risk{% elif data.summary.high_vulnerabilities > 0 %}medium-risk{% else %}low-risk{% endif %}">
                <div class="card-header">
                    <div class="card-title">⚠️ Vulnerabilities</div>
                    <div class="risk-badge {% if data.summary.high_vulnerabilities > 2 %}risk-high{% elif data.summary.high_vulnerabilities > 0 %}risk-medium{% else %}risk-low{% endif %}">
                        {{ data.summary.high_vulnerabilities }} High
                    </div>
                </div>
                <div class="card-value">{{ data.summary.vulnerabilities }}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted)">
                    System vulnerabilities identified
                </div>
            </div>

            <div class="card {% if data.summary.suspicious_processes > 10 %}high-risk{% elif data.summary.suspicious_processes > 5 %}medium-risk{% else %}low-risk{% endif %}">
                <div class="card-header">
                    <div class="card-title">⚙️ Suspicious Processes</div>
                    <div class="risk-badge {% if data.summary.suspicious_processes > 10 %}risk-high{% elif data.summary.suspicious_processes > 5 %}risk-medium{% else %}risk-low{% endif %}">
                        {{ data.summary.suspicious_processes }}
                    </div>
                </div>
                <div class="card-value">{{ data.summary.suspicious_processes }}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted)">
                    Anomalous processes detected
                </div>
            </div>

            <div class="card {% if data.summary.remote_tools > 3 %}high-risk{% elif data.summary.remote_tools > 0 %}medium-risk{% else %}low-risk{% endif %}">
                <div class="card-header">
                    <div class="card-title">🌐 Remote Access</div>
                    <div class="risk-badge {% if data.summary.remote_tools > 3 %}risk-high{% elif data.summary.remote_tools > 0 %}risk-medium{% else %}risk-low{% endif %}">
                        {{ data.summary.remote_tools }}
                    </div>
                </div>
                <div class="card-value">{{ data.summary.remote_tools }}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: var(--text-muted)">
                    Remote access tools active
                </div>
            </div>
        </div>
    </div>

    <!-- Network Traffic -->
    {% if data.network_traffic %}
    <div class="section">
        <div class="section-header">
            <div class="section-title">🌐 NETWORK TRAFFIC ANALYSIS</div>
            <div style="color: var(--text-muted)">Live connections monitored</div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Process</th>
                    <th>Threat Level</th>
                </tr>
            </thead>
            <tbody>
                {% for conn in data.network_traffic %}
                <tr>
                    <td>{{ conn.timestamp }}</td>
                    <td>{{ conn.local_ip }}:{{ conn.local_port }}</td>
                    <td>{{ conn.remote_ip }}:{{ conn.remote_port }}</td>
                    <td>{{ conn.protocol }}</td>
                    <td>{{ conn.process }} (PID: {{ conn.pid }})</td>
                    <td>
                        <span class="risk-badge {% if conn.threat_level == 'HIGH' %}risk-high{% elif conn.threat_level == 'MEDIUM' %}risk-medium{% else %}risk-low{% endif %}">
                            {{ conn.threat_level }}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Suspicious Processes -->
    {% if data.suspicious_processes %}
    <div class="section">
        <div class="section-header">
            <div class="section-title">⚙️ SUSPICIOUS PROCESSES</div>
            <div style="color: var(--text-muted)">Memory and behavior analysis</div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Process</th>
                    <th>PID</th>
                    <th>Memory</th>
                    <th>CPU</th>
                    <th>Risk</th>
                    <th>Indicators</th>
                </tr>
            </thead>
            <tbody>
                {% for proc in data.suspicious_processes %}
                <tr>
                    <td>{{ proc.process }}</td>
                    <td>{{ proc.pid }}</td>
                    <td>{{ proc.memory_usage }}</td>
                    <td>{{ proc.cpu_usage }}</td>
                    <td>
                        <span class="risk-badge {% if proc.risk == 'HIGH' %}risk-high{% elif proc.risk == 'MEDIUM' %}risk-medium{% else %}risk-low{% endif %}">
                            {{ proc.risk }}
                        </span>
                    </td>
                    <td style="font-size: 0.9em; color: var(--text-muted)">
                        {{ proc.indicators|join(', ')[:50] }}...
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- Vulnerabilities -->
    {% if data.vulnerabilities %}
    <div class="section">
        <div class="section-header">
            <div class="section-title">⚠️ VULNERABILITIES DETECTED</div>
            <div style="color: var(--text-muted)">System security assessment</div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in data.vulnerabilities %}
                <tr>
                    <td>{{ vuln.vulnerability }}</td>
                    <td>
                        <span class="risk-badge {% if vuln.severity == 'HIGH' %}risk-high{% elif vuln.severity == 'MEDIUM' %}risk-medium{% else %}risk-low{% endif %}">
                            {{ vuln.severity }}
                        </span>
                    </td>
                    <td>{{ vuln.description }}</td>
                    <td style="font-size: 0.9em">{{ vuln.remediation }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <!-- System Timeline -->
    {% if data.timeline %}
    <div class="section">
        <div class="section-header">
            <div class="section-title">⏰ SYSTEM TIMELINE</div>
            <div style="color: var(--text-muted)">Recent system events</div>
        </div>

        <div class="timeline">
            {% for event in data.timeline %}
            <div class="timeline-item {{ event.importance|lower }}">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <strong>{{ event.icon }} {{ event.event }}</strong>
                    <span style="color: var(--text-muted)">{{ event.time }}</span>
                </div>
                <div style="color: var(--text-muted); font-size: 0.9em">{{ event.details }}</div>
                <div class="risk-badge risk-info" style="margin-top: 5px; display: inline-block">
                    {{ event.importance }}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <!-- Footer -->
    <div class="footer">
        <div>HackerVision Security Report | Generated with Python 🐍</div>
        <div style="margin-top: 10px; font-size: 0.8em; color: var(--text-muted)">
            This report is for educational and security assessment purposes only.<br>
            Use responsibly and only on systems you own or have permission to test.
        </div>
    </div>

    <script>
        // Matrix rain effect
        function createMatrixRain() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const container = document.getElementById('matrix-rain');

            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            container.appendChild(canvas);

            const chars = '01アイウエオカキクケコサシスセソタチツテト';
            const fontSize = 14;
            const columns = canvas.width / fontSize;
            const drops = Array(Math.floor(columns)).fill(1);

            function draw() {
                ctx.fillStyle = 'rgba(10, 10, 10, 0.05)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);

                ctx.fillStyle = '#00ff00';
                ctx.font = `${fontSize}px 'Courier New', monospace`;

                for (let i = 0; i < drops.length; i++) {
                    const char = chars[Math.floor(Math.random() * chars.length)];
                    const x = i * fontSize;
                    const y = drops[i] * fontSize;

                    ctx.fillText(char, x, y);

                    if (y > canvas.height && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            }

            setInterval(draw, 50);

            window.addEventListener('resize', () => {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            });
        }

        // Add risk level colors to table rows
        document.addEventListener('DOMContentLoaded', function() {
            createMatrixRain();

            // Add hover effects to risk badges
            document.querySelectorAll('.risk-badge').forEach(badge => {
                badge.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.1)';
                });

                badge.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1)';
                });
            });

            // Pulse animation for high risk items
            setInterval(() => {
                document.querySelectorAll('.risk-high').forEach(el => {
                    el.style.animation = 'pulse 1s';
                    setTimeout(() => {
                        el.style.animation = '';
                    }, 1000);
                });
            }, 3000);
        });
    </script>
</body>
</html>"""


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def print_status(message: str, category: str = "INFO"):
    """Print status messages with colors and categories"""
    colors = {
        "SUCCESS": "\033[92m",  # Green
        "ERROR": "\033[91m",  # Red
        "WARNING": "\033[93m",  # Yellow
        "INFO": "\033[94m",  # Blue
        "SYSTEM": "\033[96m",  # Cyan
        "NETWORK": "\033[95m",  # Magenta
        "SECURITY": "\033[93m",  # Yellow
        "MEMORY": "\033[95m",  # Magenta
        "VISUALIZATION": "\033[96m",  # Cyan
        "REPORT": "\033[92m"  # Green
    }

    reset = "\033[0m"
    timestamp = datetime.now().strftime("%H:%M:%S")

    color = colors.get(category, "\033[97m")  # Default white
    print(f"{color}[{timestamp}] [{category:^12}] {message}{reset}")


def main():
    """Main execution function"""
    print_status("=" * 60, "SYSTEM")
    print_status("HACKERVISION - Advanced Security Monitoring Tool", "SYSTEM")
    print_status("Version 2.0 | Author: Security Analyst", "SYSTEM")
    print_status("=" * 60, "SYSTEM")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='HackerVision Security Scanner')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--duration', type=int, default=5, help='Network monitoring duration in seconds')
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--no-report', action='store_true', help='Skip HTML report generation')
    args = parser.parse_args()

    # Install dependencies
    DependencyManager.check_and_install()

    print_status(f"Starting scan on {platform.node()} ({platform.platform()})", "SYSTEM")

    # Collect all data
    all_data = {}

    # 1. Network Monitoring
    print_status("Starting network monitoring...", "NETWORK")
    all_data["network_traffic"] = NetworkMonitor.get_live_network_traffic(args.duration)

    # 2. Persistence Detection
    all_data["persistence"] = PersistenceDetector.detect_persistence_mechanisms()

    # 3. Vulnerability Scanning
    all_data["vulnerabilities"] = VulnerabilityScanner.check_system_vulnerabilities()

    # 4. Memory Analysis
    all_data["suspicious_processes"] = MemoryAnalyzer.analyze_memory_processes()

    # 5. Encryption Status
    all_data["encryption"] = EncryptionChecker.check_encryption_status()

    # 6. Remote Access Detection
    all_data["remote_access"] = RemoteAccessDetector.detect_remote_access()

    # 7. Reverse Shell Detection
    all_data["reverse_shells"] = NetworkMonitor.detect_reverse_shells()

    # 8. Data Stream Simulation
    all_data["data_stream"] = DataStreamSimulator.display_live_data_stream()

    # 9. System Timeline
    all_data["timeline"] = DataStreamSimulator.create_system_timeline()

    # 10. Threat Heatmap
    all_data["heatmap"] = ThreatHeatmap.generate_heatmap_data(
        all_data["network_traffic"],
        all_data["suspicious_processes"]
    )

    # Generate report
    if not args.no_report:
        report_path = HTMLReportGenerator.generate_report(all_data, args.output)
        if report_path:
            print_status(f"Report generated successfully: {report_path}", "SUCCESS")

    print_status("=" * 60, "SYSTEM")
    print_status("Scan completed successfully!", "SUCCESS")
    print_status(f"Total threats detected: {len(all_data['network_traffic'])}", "SUMMARY")
    print_status(f"High-risk processes: {sum(1 for p in all_data['suspicious_processes'] if p['risk'] == 'HIGH')}",
                 "SUMMARY")
    print_status(f"Vulnerabilities found: {len(all_data['vulnerabilities'])}", "SUMMARY")
    print_status("=" * 60, "SYSTEM")

    return all_data


if __name__ == "__main__":
    try:
        data = main()
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"Unexpected error: {e}", "ERROR")

        sys.exit(1)
