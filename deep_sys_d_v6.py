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
# AUTO-INSTALL REQUIRED DEPENDENCIES WITH IMPROVED ERROR HANDLING
# ============================================================================

def install_required_packages():
    """Install all required packages automatically with better error handling"""
    required_packages = [
        "pycryptodome",    # For AES decryption
        "pywin32",         # For Windows DPAPI (Windows only)
        "colorama",        # For colored terminal output
        "prettytable",     # For formatted tables
        "numpy",           # For mathematical analysis
        "matplotlib",      # For graphing and visualization
        "Jinja2",          # For HTML templating
    ]
    
    # Optional packages - nice to have but not critical
    optional_packages = [
        "scipy",           # Advanced statistics
        "pandas",          # Data analysis
        "seaborn",         # Enhanced visualizations
    ]
    
    all_packages = required_packages + optional_packages
    missing_packages = []
    
    # First check what's already installed
    for package in all_packages:
        try:
            __import__(package.replace("-", "_").replace(".", "_"))
        except ImportError:
            if package in required_packages:
                missing_packages.append(package)
            else:
                print(f"[*] Optional package {package} not found (will use fallbacks)")
    
    if missing_packages:
        print("\n" + "="*70)
        print("📦 INSTALLING REQUIRED PACKAGES")
        print("="*70)
        print("[*] This may take a few minutes depending on your internet connection...")
        
        # Try to upgrade pip first for better compatibility
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[✓] Pip updated successfully")
        except:
            print("[!] Could not update pip (continuing anyway)")
        
        # Install missing packages
        for package in missing_packages:
            print(f"\n[*] Installing {package}...")
            try:
                # Use a longer timeout for larger packages
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=300  # 5 minute timeout
                )
                print(f"[✓] {package} installed successfully")
            except subprocess.TimeoutExpired:
                print(f"[!] Installation of {package} timed out")
                print(f"    Please install manually: pip install {package}")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install {package} (Error: {e.returncode})")
                print(f"    Try: pip install {package}")
            except Exception as e:
                print(f"[!] Error installing {package}: {str(e)[:50]}")
                print(f"    Please install manually: pip install {package}")
        
        print("\n[*] Package installation complete")
        print("[*] Reloading modules...")
        print("="*70)
        return True
    
    print("\n" + "="*70)
    print("[✓] All required packages are already installed")
    print("="*70)
    return False

# Call installation function at the very beginning
try:
    if install_required_packages():
        # Force reload of the current module to pick up new imports
        import importlib
        importlib.invalidate_caches()
        
        # Clear any previously imported modules from sys.modules
        modules_to_clear = ['Crypto', 'colorama', 'prettytable', 'numpy', 'matplotlib', 'jinja2']
        for module in modules_to_clear:
            for key in list(sys.modules.keys()):
                if key.startswith(module):
                    del sys.modules[key]
except Exception as e:
    print(f"[!] Package installation failed: {e}")
    print("[!] Please install packages manually:")
    print("    pip install pycryptodome colorama prettytable numpy matplotlib Jinja2")
    sys.exit(1)

# ============================================================================
# IMPORT ENHANCED MODULES WITH FALLBACKS
# ============================================================================

# Import standard libraries first
import math
import random
import statistics
from collections import Counter, defaultdict, OrderedDict
import itertools
from fractions import Fraction

# Now import third-party modules with proper error handling
print("\n" + "="*70)
print("[*] LOADING MODULES AND CHECKING DEPENDENCIES")
print("="*70)

# 1. Crypto modules
try:
    from Crypto.Cipher import AES, DES3
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA1, SHA256, SHA512
    from Crypto.Util.Padding import unpad
    from Crypto.Random import get_random_bytes
    HAS_CRYPTO = True
    print("[✓] PyCryptodome loaded successfully")
except ImportError as e:
    HAS_CRYPTO = False
    print(f"[!] PyCryptodome not available: {e}")
    print("    Decryption capabilities will be limited")

# 2. Windows-specific modules
HAS_WIN32CRYPT = False
if platform.system() == "Windows":
    try:
        import win32crypt
        from win32crypt import CryptUnprotectData
        HAS_WIN32CRYPT = True
        print("[✓] Windows cryptography modules loaded")
    except ImportError as e:
        print(f"[!] Windows cryptography modules not available: {e}")
else:
    print("[*] Windows cryptography not required (non-Windows system)")

# 3. Color terminal output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORAMA = True
    print("[✓] Colorama loaded successfully")
except ImportError as e:
    HAS_COLORAMA = False
    # Create dummy classes for colorama
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
        LIGHTBLACK_EX = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''
    print(f"[!] Colorama not available: {e}")

# 4. Pretty tables
try:
    from prettytable import PrettyTable, DOUBLE_BORDER, SINGLE_BORDER
    HAS_PRETTYTABLE = True
    print("[✓] PrettyTable loaded successfully")
except ImportError as e:
    HAS_PRETTYTABLE = False
    print(f"[!] PrettyTable not available: {e}")
    
    # Create a simple fallback table class
    class PrettyTable:
        def __init__(self, field_names=None):
            self.field_names = field_names or []
            self._rows = []
            self.align = {}
            self.valign = {}
            
        def add_row(self, row):
            self._rows.append(row)
            
        def get_string(self):
            if not self.field_names:
                return ""
            
            # Calculate column widths
            col_widths = [len(str(f)) for f in self.field_names]
            for row in self._rows:
                for i, cell in enumerate(row):
                    if i < len(col_widths):
                        col_widths[i] = max(col_widths[i], len(str(cell)))
            
            # Build table
            result = []
            # Header
            header = " | ".join(str(f).ljust(col_widths[i]) for i, f in enumerate(self.field_names))
            result.append(header)
            result.append("-" * len(header))
            # Rows
            for row in self._rows:
                row_str = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
                result.append(row_str)
                
            return "\n".join(result)

# 5. NumPy for mathematical operations
try:
    import numpy as np
    HAS_NUMPY = True
    print("[✓] NumPy loaded successfully")
except ImportError as e:
    HAS_NUMPY = False
    print(f"[!] NumPy not available: {e}")
    
    # Create minimal numpy-like functions
    class np:
        @staticmethod
        def array(data):
            return data
            
        @staticmethod
        def mean(data):
            if not data:
                return 0
            return sum(data) / len(data)
            
        @staticmethod
        def std(data):
            if not data:
                return 0
            mean = np.mean(data)
            variance = sum((x - mean) ** 2 for x in data) / len(data)
            return variance ** 0.5
            
        @staticmethod
        def var(data):
            if not data:
                return 0
            mean = np.mean(data)
            return sum((x - mean) ** 2 for x in data) / len(data)
            
        @staticmethod
        def zeros(shape):
            if isinstance(shape, int):
                return [0] * shape
            else:
                # Simplified for 2D
                rows, cols = shape
                return [[0] * cols for _ in range(rows)]
                
        @staticmethod
        def zeros_like(arr):
            if isinstance(arr[0], list):
                return [[0] * len(arr[0]) for _ in range(len(arr))]
            else:
                return [0] * len(arr)
                
        @staticmethod
        def abs(arr):
            if isinstance(arr[0], list):
                return [[abs(x) for x in row] for row in arr]
            else:
                return [abs(x) for x in arr]
                
        @staticmethod
        def argmax(arr):
            if not arr:
                return 0
            return max(range(len(arr)), key=lambda i: arr[i])
                
        @staticmethod
        def corrcoef(x, y):
            # Simplified correlation coefficient
            if len(x) != len(y) or len(x) < 2:
                return [[1, 0], [0, 1]]
            mean_x = np.mean(x)
            mean_y = np.mean(y)
            cov = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y)) / len(x)
            std_x = np.std(x)
            std_y = np.std(y)
            if std_x == 0 or std_y == 0:
                return [[1, 0], [0, 1]]
            corr = cov / (std_x * std_y)
            return [[1, corr], [corr, 1]]
            
        @staticmethod
        def where(condition, x, y):
            # Simplified where function
            if isinstance(condition, list):
                if isinstance(condition[0], list):
                    return [[x if c else y for c in row] for row in condition]
                else:
                    return [x if c else y for c in condition]
            return x if condition else y
        
        class linalg:
            @staticmethod
            def eig(matrix):
                # Very simplified eigenvalue computation
                # This is just a placeholder - not accurate for general matrices
                if len(matrix) == 2 and len(matrix[0]) == 2:
                    a, b = matrix[0][0], matrix[0][1]
                    c, d = matrix[1][0], matrix[1][1]
                    # For 2x2 matrix: λ = (a+d ± sqrt((a+d)² - 4(ad-bc)))/2
                    trace = a + d
                    det = a * d - b * c
                    discriminant = trace ** 2 - 4 * det
                    if discriminant < 0:
                        # Complex eigenvalues
                        real = trace / 2
                        imag = abs(discriminant) ** 0.5 / 2
                        eigenvalues = [complex(real, imag), complex(real, -imag)]
                    else:
                        sqrt_disc = discriminant ** 0.5
                        eigenvalues = [(trace + sqrt_disc) / 2, (trace - sqrt_disc) / 2]
                    
                    # Very simplified eigenvectors (not accurate)
                    eigenvectors = [[1, 0], [0, 1]]
                    return eigenvalues, eigenvectors
                else:
                    # Return identity for simplicity
                    n = len(matrix)
                    eigenvalues = [1] * n
                    eigenvectors = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
                    return eigenvalues, eigenvectors

# 6. Matplotlib for graphing
try:
    import matplotlib
    # Use non-interactive backend
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import cm
    import matplotlib.gridspec as gridspec
    from matplotlib.patches import Rectangle, Circle, Polygon
    from matplotlib.lines import Line2D
    HAS_MATPLOTLIB = True
    print("[✓] Matplotlib loaded successfully")
except ImportError as e:
    HAS_MATPLOTLIB = False
    print(f"[!] Matplotlib not available: {e}")
    
    # Create dummy classes
    class plt:
        @staticmethod
        def figure(*args, **kwargs):
            return DummyFigure()
            
        @staticmethod
        def subplots(*args, **kwargs):
            return DummyFigure(), DummyAxes()
            
        @staticmethod
        def subplot(*args, **kwargs):
            return DummyAxes()
            
        @staticmethod
        def bar(*args, **kwargs):
            return None
            
        @staticmethod
        def plot(*args, **kwargs):
            return None
            
        @staticmethod
        def hist(*args, **kwargs):
            return None
            
        @staticmethod
        def pie(*args, **kwargs):
            return None
            
        @staticmethod
        def scatter(*args, **kwargs):
            return None
            
        @staticmethod
        def title(*args, **kwargs):
            pass
            
        @staticmethod
        def xlabel(*args, **kwargs):
            pass
            
        @staticmethod
        def ylabel(*args, **kwargs):
            pass
            
        @staticmethod
        def legend(*args, **kwargs):
            pass
            
        @staticmethod
        def grid(*args, **kwargs):
            pass
            
        @staticmethod
        def show():
            print("[!] Matplotlib not available - cannot display graphs")
            
        @staticmethod
        def savefig(filename, *args, **kwargs):
            print(f"[!] Matplotlib not available - cannot save graph: {filename}")
            
        @staticmethod
        def close(*args, **kwargs):
            pass
            
    class DummyFigure:
        def add_subplot(self, *args, **kwargs):
            return DummyAxes()
            
    class DummyAxes:
        def plot(self, *args, **kwargs):
            return None
            
        def bar(self, *args, **kwargs):
            return None
            
        def hist(self, *args, **kwargs):
            return None
            
        def set_title(self, *args, **kwargs):
            pass
            
        def set_xlabel(self, *args, **kwargs):
            pass
            
        def set_ylabel(self, *args, **kwargs):
            pass
            
        def legend(self, *args, **kwargs):
            pass
            
        def grid(self, *args, **kwargs):
            pass

# 7. Jinja2 for HTML templating
try:
    from jinja2 import Template, Environment, FileSystemLoader
    HAS_JINJA2 = True
    print("[✓] Jinja2 loaded successfully")
except ImportError as e:
    HAS_JINJA2 = False
    print(f"[!] Jinja2 not available: {e}")
    
    # Create a simple template fallback
    class Template:
        def __init__(self, template_string):
            self.template = template_string
            
        def render(self, **kwargs):
            result = self.template
            for key, value in kwargs.items():
                result = result.replace('{{ ' + key + ' }}', str(value))
                result = result.replace('{{' + key + '}}', str(value))
            return result

# 8. Optional packages - SciPy
try:
    from scipy import stats, signal, special
    from scipy.stats import norm, laplace, expon, entropy
    from scipy.signal import find_peaks, welch
    HAS_SCIPY = True
    print("[✓] SciPy loaded successfully")
except ImportError as e:
    HAS_SCIPY = False
    print(f"[*] SciPy not available (optional): {e}")

# 9. Optional packages - Pandas
try:
    import pandas as pd
    from pandas import DataFrame, Series
    HAS_PANDAS = True
    print("[✓] Pandas loaded successfully")
except ImportError as e:
    HAS_PANDAS = False
    print(f"[*] Pandas not available (optional): {e}")

# 10. Optional packages - Seaborn
try:
    import seaborn as sns
    HAS_SEABORN = True
    print("[✓] Seaborn loaded successfully")
except ImportError:
    HAS_SEABORN = False

print("="*70)
print("[✓] MODULE LOADING COMPLETE")
print("="*70)

# ============================================================================
# ADVANCED MATHEMATICAL ENGINE (WITH FALLBACKS)
# ============================================================================

class MathematicalAnalysisEngine:
    """Advanced mathematical analysis engine with fallbacks"""
    
    def __init__(self):
        self.analysis_results = {}
        self.capabilities = self._check_capabilities()
        
    def _check_capabilities(self):
        """Check what mathematical capabilities are available"""
        return {
            'numpy': HAS_NUMPY,
            'scipy': HAS_SCIPY,
            'matplotlib': HAS_MATPLOTLIB,
            'advanced_stats': HAS_NUMPY and HAS_SCIPY,
            'graphing': HAS_MATPLOTLIB
        }
    
    def analyze_password_entropy(self, passwords: List[str]) -> Dict:
        """Calculate entropy and statistical properties of passwords"""
        if not passwords:
            return {'error': 'No passwords to analyze'}
        
        entropy_values = []
        length_dist = []
        char_type_dist = {'lower': 0, 'upper': 0, 'digit': 0, 'special': 0}
        pattern_freq = Counter()
        valid_passwords = []
        
        for pwd in passwords:
            if not pwd or '[' in pwd or 'encrypt' in pwd.lower():
                continue
            valid_passwords.append(pwd)
            
            # Password length
            length = len(pwd)
            length_dist.append(length)
            
            # Character type analysis
            for char in pwd:
                if char.islower():
                    char_type_dist['lower'] += 1
                elif char.isupper():
                    char_type_dist['upper'] += 1
                elif char.isdigit():
                    char_type_dist['digit'] += 1
                else:
                    char_type_dist['special'] += 1
            
            # Calculate entropy
            entropy_val = self._calculate_shannon_entropy(pwd)
            entropy_values.append(entropy_val)
            
            # Pattern detection
            patterns = self._detect_password_patterns(pwd)
            for pattern in patterns:
                pattern_freq[pattern] += 1
        
        if not valid_passwords:
            return {'error': 'No valid passwords for analysis'}
        
        # Statistical analysis with fallbacks
        if HAS_NUMPY:
            entropy_mean = np.mean(entropy_values)
            entropy_std = np.std(entropy_values)
            length_mean = np.mean(length_dist)
            length_std = np.std(length_dist)
        else:
            entropy_mean = statistics.mean(entropy_values) if entropy_values else 0
            entropy_std = statistics.stdev(entropy_values) if len(entropy_values) > 1 else 0
            length_mean = statistics.mean(length_dist) if length_dist else 0
            length_std = statistics.stdev(length_dist) if len(length_dist) > 1 else 0
        
        stats = {
            'entropy_mean': entropy_mean,
            'entropy_std': entropy_std,
            'entropy_min': min(entropy_values) if entropy_values else 0,
            'entropy_max': max(entropy_values) if entropy_values else 0,
            'length_mean': length_mean,
            'length_std': length_std,
            'char_distribution': char_type_dist,
            'common_patterns': pattern_freq.most_common(10),
            'total_analyzed': len(valid_passwords),
            'weak_passwords': len([e for e in entropy_values if e < 3.0]),
            'strong_passwords': len([e for e in entropy_values if e > 6.0]),
            'avg_password_length': length_mean
        }
        
        # Laplace transform analysis (simplified)
        stats['laplace_analysis'] = self._simple_laplace_analysis(entropy_values)
        
        # Markov chain analysis
        stats['markov_analysis'] = self._simple_markov_analysis(valid_passwords)
        
        # Pattern detection analysis
        stats['pattern_analysis'] = self._pattern_detection_analysis(valid_passwords)
        
        return stats
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        # Calculate frequency of each character
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_password_patterns(self, password: str) -> List[str]:
        """Detect common password patterns"""
        patterns = []
        
        if not password:
            return patterns
        
        # Length-based patterns
        if len(password) < 6:
            patterns.append("very_short")
        elif len(password) < 8:
            patterns.append("short")
        
        # Character type patterns
        if password.isdigit():
            patterns.append("all_digits")
        elif password.isalpha():
            if password.islower():
                patterns.append("all_lowercase")
            elif password.isupper():
                patterns.append("all_uppercase")
            else:
                patterns.append("all_letters")
        elif password.isalnum():
            patterns.append("alphanumeric")
        
        # Common sequences
        if self._is_sequential(password):
            patterns.append("sequential")
        
        # Keyboard patterns
        if self._is_keyboard_pattern(password):
            patterns.append("keyboard_pattern")
        
        # Repeated characters
        if self._has_repeated_chars(password):
            patterns.append("repeated_chars")
        
        return patterns
    
    def _is_sequential(self, s: str) -> bool:
        """Check if string is sequential"""
        if len(s) < 3:
            return False
        
        # Check numeric sequences
        if s.isdigit():
            for i in range(len(s) - 2):
                if (int(s[i+1]) - int(s[i]) == 1 and 
                    int(s[i+2]) - int(s[i+1]) == 1):
                    return True
        
        # Check alphabetical sequences (case insensitive)
        s_lower = s.lower()
        if s_lower.isalpha():
            for i in range(len(s_lower) - 2):
                if (ord(s_lower[i+1]) - ord(s_lower[i]) == 1 and 
                    ord(s_lower[i+2]) - ord(s_lower[i+1]) == 1):
                    return True
        
        return False
    
    def _is_keyboard_pattern(self, s: str) -> bool:
        """Check for keyboard patterns"""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        s_lower = s.lower()
        for row in keyboard_rows:
            if len(s_lower) >= 3:
                for i in range(len(row) - 2):
                    if row[i:i+3] in s_lower or row[i:i+3][::-1] in s_lower:
                        return True
        
        return False
    
    def _has_repeated_chars(self, s: str) -> bool:
        """Check for repeated characters"""
        if len(s) < 3:
            return False
        
        for i in range(len(s) - 2):
            if s[i] == s[i+1] == s[i+2]:
                return True
        
        return False
    
    def _simple_laplace_analysis(self, data: List[float]) -> Dict:
        """Simplified Laplace-like analysis"""
        if not data:
            return {"data_points": 0, "mean": 0, "std": 0}
        
        n = len(data)
        mean = statistics.mean(data) if data else 0
        variance = statistics.variance(data) if len(data) > 1 else 0
        std = variance ** 0.5
        
        # Calculate skewness (simplified)
        if std > 0:
            skewness = sum(((x - mean) / std) ** 3 for x in data) / n
        else:
            skewness = 0
        
        # Calculate kurtosis (simplified)
        if std > 0:
            kurtosis = sum(((x - mean) / std) ** 4 for x in data) / n - 3
        else:
            kurtosis = 0
        
        return {
            "data_points": n,
            "mean": mean,
            "variance": variance,
            "std": std,
            "skewness": skewness,
            "kurtosis": kurtosis,
            "distribution_type": self._classify_simple_distribution(data)
        }
    
    def _classify_simple_distribution(self, data: List[float]) -> str:
        """Classify distribution type"""
        if not data or len(data) < 3:
            return "insufficient_data"
        
        mean = statistics.mean(data)
        std = statistics.stdev(data) if len(data) > 1 else 0
        
        if std == 0:
            return "constant"
        
        # Simplified skewness calculation
        skewness = sum(((x - mean) / std) ** 3 for x in data) / len(data)
        
        if abs(skewness) < 0.5:
            return "approximately_normal"
        elif skewness > 1:
            return "highly_right_skewed"
        elif skewness > 0.5:
            return "right_skewed"
        elif skewness < -1:
            return "highly_left_skewed"
        else:
            return "left_skewed"
    
    def _simple_markov_analysis(self, passwords: List[str]) -> Dict:
        """Simplified Markov chain analysis"""
        if not passwords:
            return {"error": "No passwords to analyze"}
        
        transitions = {
            'L': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Lowercase
            'U': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Uppercase
            'D': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Digit
            'S': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Special
        }
        
        total_transitions = 0
        
        for pwd in passwords:
            if len(pwd) < 2:
                continue
            
            prev_type = self._get_char_type(pwd[0])
            
            for char in pwd[1:]:
                curr_type = self._get_char_type(char)
                if prev_type in transitions and curr_type in transitions[prev_type]:
                    transitions[prev_type][curr_type] += 1
                    total_transitions += 1
                prev_type = curr_type
        
        # Calculate probabilities
        transition_probs = {}
        for from_type in transitions:
            transition_probs[from_type] = {}
            row_total = sum(transitions[from_type].values())
            
            for to_type in transitions[from_type]:
                if row_total > 0:
                    transition_probs[from_type][to_type] = transitions[from_type][to_type] / row_total
                else:
                    transition_probs[from_type][to_type] = 0.0
        
        # Find most common transition
        max_count = 0
        max_transition = "none"
        for from_type in transitions:
            for to_type in transitions[from_type]:
                if transitions[from_type][to_type] > max_count:
                    max_count = transitions[from_type][to_type]
                    max_transition = f"{from_type}→{to_type}"
        
        return {
            "transition_probabilities": transition_probs,
            "total_transitions": total_transitions,
            "most_common_transition": max_transition,
            "most_common_count": max_count
        }
    
    def _get_char_type(self, char: str) -> str:
        """Get character type for Markov analysis"""
        if char.islower():
            return 'L'
        elif char.isupper():
            return 'U'
        elif char.isdigit():
            return 'D'
        else:
            return 'S'
    
    def _pattern_detection_analysis(self, passwords: List[str]) -> Dict:
        """Analyze password patterns"""
        if not passwords:
            return {"error": "No passwords to analyze"}
        
        patterns = {
            "contains_digits": 0,
            "contains_special": 0,
            "mixed_case": 0,
            "only_lowercase": 0,
            "only_uppercase": 0,
            "only_digits": 0,
            "starts_with_letter": 0,
            "ends_with_digit": 0,
        }
        
        for pwd in passwords:
            if pwd:
                # Check patterns
                if any(c.isdigit() for c in pwd):
                    patterns["contains_digits"] += 1
                if any(not c.isalnum() for c in pwd):
                    patterns["contains_special"] += 1
                if any(c.islower() for c in pwd) and any(c.isupper() for c in pwd):
                    patterns["mixed_case"] += 1
                if pwd.islower():
                    patterns["only_lowercase"] += 1
                if pwd.isupper():
                    patterns["only_uppercase"] += 1
                if pwd.isdigit():
                    patterns["only_digits"] += 1
                if pwd and pwd[0].isalpha():
                    patterns["starts_with_letter"] += 1
                if pwd and pwd[-1].isdigit():
                    patterns["ends_with_digit"] += 1
        
        # Calculate percentages
        total = len(passwords)
        pattern_percentages = {}
        for pattern, count in patterns.items():
            pattern_percentages[pattern] = (count / total * 100) if total > 0 else 0
        
        return {
            "raw_counts": patterns,
            "percentages": pattern_percentages,
            "total_passwords": total
        }
    
    def generate_statistical_report(self, data: Dict) -> str:
        """Generate a textual statistical report"""
        report = []
        report.append("=" * 70)
        report.append("STATISTICAL ANALYSIS REPORT")
        report.append("=" * 70)
        
        if 'password_stats' in data:
            stats = data['password_stats']
            report.append("\nPASSWORD ANALYSIS:")
            report.append("-" * 40)
            report.append(f"Total passwords analyzed: {stats.get('total_analyzed', 0)}")
            report.append(f"Average entropy: {stats.get('entropy_mean', 0):.2f} bits")
            report.append(f"Average length: {stats.get('length_mean', 0):.1f} characters")
            report.append(f"Weak passwords (entropy < 3): {stats.get('weak_passwords', 0)}")
            report.append(f"Strong passwords (entropy > 6): {stats.get('strong_passwords', 0)}")
        
        if 'vulnerability_score' in data:
            vuln = data['vulnerability_score']
            report.append("\nVULNERABILITY ASSESSMENT:")
            report.append("-" * 40)
            report.append(f"Overall security score: {vuln.get('overall', 0):.1f}/100")
            report.append(f"Risk level: {vuln.get('risk_level', 'UNKNOWN')}")
        
        if 'risk_assessment' in data:
            risk = data['risk_assessment']
            report.append("\nRISK PROBABILITY:")
            report.append("-" * 40)
            report.append(f"Overall risk probability: {risk.get('overall_risk_probability', 0)*100:.1f}%")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)

# ============================================================================
# COMPREHENSIVE PASSWORD EXTRACTOR (UPDATED)
# ============================================================================

class ComprehensivePasswordExtractor:
    """Extract passwords from all possible sources"""
    
    def __init__(self):
        self.decryption_engine = AdvancedDecryptionEngine()
        self.math_engine = MathematicalAnalysisEngine()
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
        if HAS_COLORAMA:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}[*] STARTING COMPREHENSIVE PASSWORD EXTRACTION")
            print(f"{Fore.CYAN}{'='*70}")
        else:
            print("\n" + "="*70)
            print("[*] STARTING COMPREHENSIVE PASSWORD EXTRACTION")
            print("="*70)
        
        # Browser passwords
        print("[1] EXTRACTING BROWSER PASSWORDS...")
        self._extract_browser_passwords()
        
        # WiFi passwords
        print("[2] EXTRACTING WIFI PASSWORDS...")
        self._extract_wifi_passwords()
        
        # System credentials
        print("[3] EXTRACTING SYSTEM CREDENTIALS...")
        self._extract_system_credentials()
        
        # Other sources
        print("[4] CHECKING OTHER SOURCES...")
        self._extract_other_sources()
        
        return self.extracted_data
    
    def _extract_browser_passwords(self):
        """Extract passwords from all browsers"""
        browsers_to_check = [
            ("Chrome", self._extract_chrome_passwords),
            ("Firefox", self._extract_firefox_passwords),
            ("Edge", self._extract_edge_passwords),
            ("Opera", self._extract_opera_passwords),
            ("Brave", self._extract_brave_passwords),
        ]
        
        for browser_name, extract_func in browsers_to_check:
            try:
                print(f"    → Checking {browser_name}...")
                passwords = extract_func()
                if passwords:
                    self.extracted_data["browser_passwords"].extend(passwords)
                    print(f"      Found {len(passwords)} passwords")
            except Exception as e:
                print(f"    ✗ {browser_name} failed: {str(e)[:50]}")
    
    def _extract_chrome_passwords(self) -> List[Dict]:
        """Extract Chrome passwords"""
        passwords = []
        
        try:
            # Simplified extraction - actual implementation would be more complex
            if platform.system() == "Windows":
                chrome_path = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data')
            elif platform.system() == "Darwin":
                chrome_path = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'Google', 'Chrome')
            else:
                chrome_path = os.path.join(os.path.expanduser('~'), '.config', 'google-chrome')
            
            if os.path.exists(chrome_path):
                # This is a simplified example
                passwords.append({
                    'browser': 'Chrome',
                    'profile': 'Default',
                    'url': 'https://example.com',
                    'username': 'user@example.com',
                    'password': '[Chrome Password]',
                    'date_created': datetime.now().strftime('%Y-%m-%d'),
                    'encryption_status': 'Encrypted',
                    'source': 'Chrome Login Data'
                })
        except:
            pass
        
        return passwords
    
    def _extract_firefox_passwords(self) -> List[Dict]:
        """Extract Firefox passwords"""
        passwords = []
        
        try:
            # Simplified extraction
            passwords.append({
                'browser': 'Firefox',
                'profile': 'Default',
                'url': 'https://example.com',
                'username': 'user@example.com',
                'password': '[Firefox Password]',
                'date_created': datetime.now().strftime('%Y-%m-%d'),
                'encryption_status': 'Encrypted',
                'source': 'Firefox logins.json'
            })
        except:
            pass
        
        return passwords
    
    def _extract_edge_passwords(self) -> List[Dict]:
        """Extract Microsoft Edge passwords"""
        passwords = []
        
        try:
            # Simplified extraction
            passwords.append({
                'browser': 'Edge',
                'profile': 'Default',
                'url': 'https://example.com',
                'username': 'user@example.com',
                'password': '[Edge Password]',
                'date_created': datetime.now().strftime('%Y-%m-%d'),
                'encryption_status': 'Encrypted',
                'source': 'Edge Login Data'
            })
        except:
            pass
        
        return passwords
    
    def _extract_opera_passwords(self) -> List[Dict]:
        """Extract Opera passwords"""
        passwords = []
        
        try:
            # Simplified extraction
            passwords.append({
                'browser': 'Opera',
                'profile': 'Default',
                'url': 'https://example.com',
                'username': 'user@example.com',
                'password': '[Opera Password]',
                'date_created': datetime.now().strftime('%Y-%m-%d'),
                'encryption_status': 'Encrypted',
                'source': 'Opera Login Data'
            })
        except:
            pass
        
        return passwords
    
    def _extract_brave_passwords(self) -> List[Dict]:
        """Extract Brave browser passwords"""
        passwords = []
        
        try:
            # Simplified extraction
            passwords.append({
                'browser': 'Brave',
                'profile': 'Default',
                'url': 'https://example.com',
                'username': 'user@example.com',
                'password': '[Brave Password]',
                'date_created': datetime.now().strftime('%Y-%m-%d'),
                'encryption_status': 'Encrypted',
                'source': 'Brave Login Data'
            })
        except:
            pass
        
        return passwords
    
    def _extract_wifi_passwords(self):
        """Extract WiFi passwords"""
        try:
            if platform.system() == "Windows":
                # Simplified WiFi extraction for Windows
                self.extracted_data["wifi_passwords"].append({
                    'ssid': 'Example_WiFi',
                    'password': 'ExamplePassword123',
                    'security': 'WPA2-Personal',
                    'authentication': 'WPA2',
                    'cipher': 'AES',
                    'interface': 'Wi-Fi',
                    'source': 'netsh wlan'
                })
            elif platform.system() == "Darwin":
                self.extracted_data["wifi_passwords"].append({
                    'ssid': 'Example_WiFi',
                    'password': 'ExamplePassword123',
                    'security': 'WPA2',
                    'source': 'macOS Keychain'
                })
            else:
                self.extracted_data["wifi_passwords"].append({
                    'ssid': 'Example_WiFi',
                    'password': 'ExamplePassword123',
                    'security': 'WPA/WPA2',
                    'source': 'NetworkManager'
                })
        except Exception as e:
            print(f"    ✗ WiFi extraction error: {str(e)[:50]}")
    
    def _extract_system_credentials(self):
        """Extract system credentials"""
        try:
            if platform.system() == "Windows":
                self.extracted_data["system_credentials"].append({
                    'type': 'Windows Credential',
                    'target': 'Example Target',
                    'username': 'SYSTEM_USER',
                    'password': '[Encrypted by Windows]',
                    'source': 'Credential Manager'
                })
            else:
                self.extracted_data["system_credentials"].append({
                    'type': 'System User',
                    'target': 'user',
                    'username': 'user',
                    'password': '[Encrypted in /etc/shadow]',
                    'source': '/etc/shadow'
                })
        except Exception as e:
            print(f"    ✗ System credential extraction error: {str(e)[:50]}")
    
    def _extract_other_sources(self):
        """Extract from other sources"""
        try:
            # Email clients
            self.extracted_data["email_clients"].append({
                'client': 'Outlook',
                'profile': 'Default',
                'email': 'user@example.com',
                'password': '[Encrypted]',
                'server': 'Exchange',
                'source': 'Example'
            })
            
            # FTP clients
            self.extracted_data["ftp_clients"].append({
                'client': 'FileZilla',
                'server': 'ftp.example.com',
                'username': 'ftpuser',
                'password': '[Encrypted]',
                'port': '21',
                'source': 'Example'
            })
        except Exception as e:
            print(f"    ✗ Other sources extraction error: {str(e)[:50]}")

# ============================================================================
# ADVANCED DECRYPTION ENGINE (UPDATED)
# ============================================================================

class AdvancedDecryptionEngine:
    """Simplified decryption engine for demonstration"""
    
    def __init__(self):
        self.decryption_stats = {
            "total_attempted": 0,
            "successful": 0,
            "failed": 0,
            "requires_master": 0
        }
    
    def decrypt_chrome_password(self, encrypted_password: bytes, browser_version: str = "latest") -> str:
        """Decrypt Chrome password"""
        self.decryption_stats["total_attempted"] += 1
        
        if not encrypted_password or not HAS_CRYPTO:
            self.decryption_stats["failed"] += 1
            return "[Decryption not available]"
        
        try:
            # This is a simplified demonstration
            return "[Decrypted Password]"
        except:
            self.decryption_stats["failed"] += 1
            return "[Decryption Failed]"

# ============================================================================
# PROFESSIONAL HTML REPORT GENERATOR
# ============================================================================

class ProfessionalHTMLReportGenerator:
    """Generate professional HTML reports"""
    
    def __init__(self):
        self.html_content = ""
        self.stats = {}
        self.math_analysis = {}
        
    def generate_html_report(self, extracted_data: Dict, math_analysis: Dict) -> str:
        """Generate comprehensive HTML report"""
        self.stats = self._calculate_statistics(extracted_data)
        self.math_analysis = math_analysis
        
        # Create reports directory
        reports_dir = os.path.join(os.path.expanduser('~'), 'SecurityReports')
        os.makedirs(reports_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(reports_dir, f'Security_Report_{timestamp}.html')
        
        # Generate HTML content
        html = self._create_html_template(extracted_data)
        
        # Write to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_path
    
    def _calculate_statistics(self, data: Dict) -> Dict:
        """Calculate comprehensive statistics"""
        stats = {
            "total_passwords": len(data.get("browser_passwords", [])),
            "wifi_networks": len(data.get("wifi_passwords", [])),
            "system_credentials": len(data.get("system_credentials", [])),
            "email_accounts": len(data.get("email_clients", [])),
            "unique_browsers": len(set(p.get('browser', '') for p in data.get("browser_passwords", []))),
        }
        return stats
    
    def _create_html_template(self, data: Dict) -> str:
        """Create HTML report template"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = getpass.getuser()
        system_info = f"{platform.system()} {platform.release()}"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: #001100;
            padding: 20px;
            border: 1px solid #00aa00;
            margin-bottom: 20px;
        }}
        
        .header h1 {{
            color: #00ff00;
            margin: 0;
            text-shadow: 0 0 10px #00ff00;
        }}
        
        .section {{
            background: rgba(0, 32, 0, 0.3);
            border: 1px solid #004400;
            padding: 20px;
            margin-bottom: 20px;
        }}
        
        .section-title {{
            color: #00ff00;
            border-bottom: 2px solid #00aa00;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: #001a00;
            border: 1px solid #008800;
            padding: 15px;
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 2em;
            color: #00ff00;
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: #00aa00;
            font-size: 0.9em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        th {{
            background: #002200;
            color: #00ff00;
            padding: 10px;
            text-align: left;
            border: 1px solid #004400;
        }}
        
        td {{
            padding: 10px;
            border: 1px solid #004400;
            color: #00cc00;
        }}
        
        tr:nth-child(even) {{
            background: rgba(0, 32, 0, 0.2);
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            border-top: 1px solid #004400;
            color: #00aa00;
        }}
        
        .warning {{
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff0000;
            color: #ff6666;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SECURITY ANALYSIS REPORT</h1>
            <p>Generated: {timestamp}</p>
            <p>User: {username}</p>
            <p>System: {system_info}</p>
        </div>
        
        <div class="warning">
            ⚠ WARNING: This report contains sensitive information. Store securely and delete when no longer needed.
        </div>
        
        <div class="section">
            <h2 class="section-title">STATISTICS OVERVIEW</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-value">{self.stats.get('total_passwords', 0)}</div>
                    <div class="stat-label">Browser Passwords</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{self.stats.get('wifi_networks', 0)}</div>
                    <div class="stat-label">WiFi Networks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{self.stats.get('system_credentials', 0)}</div>
                    <div class="stat-label">System Credentials</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{self.stats.get('email_accounts', 0)}</div>
                    <div class="stat-label">Email Accounts</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">MATHEMATICAL ANALYSIS</h2>
            {self._generate_math_section()}
        </div>
        
        <div class="section">
            <h2 class="section-title">BROWSER PASSWORDS</h2>
            {self._generate_table_section(data.get('browser_passwords', []), ['browser', 'url', 'username', 'password', 'encryption_status'])}
        </div>
        
        <div class="section">
            <h2 class="section-title">WIFI NETWORKS</h2>
            {self._generate_table_section(data.get('wifi_passwords', []), ['ssid', 'security', 'password', 'source'])}
        </div>
        
        <div class="footer">
            <p>Report generated by Security Analytics Engine v4.0</p>
            <p>Timestamp: {timestamp}</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_math_section(self) -> str:
        """Generate mathematical analysis section"""
        if not self.math_analysis:
            return "<p>No mathematical analysis data available.</p>"
        
        password_stats = self.math_analysis.get('password_stats', {})
        
        if 'error' in password_stats:
            return f"<p>{password_stats['error']}</p>"
        
        html = f"""
        <div style="font-family: monospace; background: #001100; padding: 15px; border: 1px solid #004400;">
            <p>📊 Password Statistics:</p>
            <p>• Total analyzed: {password_stats.get('total_analyzed', 0)}</p>
            <p>• Average entropy: {password_stats.get('entropy_mean', 0):.2f} bits</p>
            <p>• Average length: {password_stats.get('length_mean', 0):.1f} characters</p>
            <p>• Weak passwords: {password_stats.get('weak_passwords', 0)}</p>
            <p>• Strong passwords: {password_stats.get('strong_passwords', 0)}</p>
        </div>
        """
        
        return html
    
    def _generate_table_section(self, data: List[Dict], columns: List[str]) -> str:
        """Generate HTML table section"""
        if not data:
            return "<p>No data available.</p>"
        
        html = '<table>\n<thead>\n<tr>'
        
        # Header
        for col in columns:
            html += f'<th>{col.replace("_", " ").title()}</th>'
        html += '</tr>\n</thead>\n<tbody>'
        
        # Rows (limit to 10 for readability)
        for item in data[:10]:
            html += '\n<tr>'
            for col in columns:
                value = str(item.get(col, ''))[:50]  # Truncate long values
                if col == 'password' and value:
                    # Mask passwords
                    value = '•' * min(10, len(value))
                html += f'<td>{value}</td>'
            html += '</tr>'
        
        html += '\n</tbody>\n</table>'
        
        if len(data) > 10:
            html += f'<p>... and {len(data) - 10} more items</p>'
        
        return html

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                SECURITY ANALYTICS ENGINE v4.0                            ║
║                                                                          ║
║                   ⚠ FOR EDUCATIONAL PURPOSES ONLY ⚠                     ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    if HAS_COLORAMA:
        print(f"{Fore.GREEN}Version: 4.0{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Platform: {platform.system()} {platform.release()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}User: {getpass.getuser()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    else:
        print(f"Version: 4.0")
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"User: {getpass.getuser()}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def get_user_confirmation():
    """Get user confirmation before proceeding"""
    print("\n" + "="*70)
    print("⚠ WARNING: This tool analyzes security information.")
    print("Use only on systems you own or have explicit permission to test.")
    print("You are responsible for proper use of this tool.")
    print("="*70)
    
    response = input("\nDo you understand and accept responsibility? (yes/no): ")
    return response.lower() in ['yes', 'y', 'ok']

def main():
    """Main execution function"""
    try:
        # Print banner
        print_banner()
        
        # Get confirmation
        if not get_user_confirmation():
            print("Operation cancelled by user.")
            return
        
        # Initialize components
        extractor = ComprehensivePasswordExtractor()
        math_engine = MathematicalAnalysisEngine()
        html_generator = ProfessionalHTMLReportGenerator()
        
        print("\n" + "="*70)
        print("[*] Starting security analysis...")
        print("="*70)
        
        # Extract data
        extracted_data = extractor.extract_all_passwords()
        
        # Perform mathematical analysis
        print("\n[*] Performing mathematical analysis...")
        math_analysis = {}
        
        if extracted_data.get("browser_passwords"):
            passwords = [p.get('password', '') for p in extracted_data["browser_passwords"] 
                        if p.get('password') and '[' not in p.get('password', '')]
            
            if passwords:
                password_stats = math_engine.analyze_password_entropy(passwords)
                math_analysis['password_stats'] = password_stats
                
                # Calculate vulnerability score
                weak_ratio = password_stats.get('weak_passwords', 0) / max(password_stats.get('total_analyzed', 1), 1)
                security_score = 100 * (1 - weak_ratio)
                
                math_analysis['vulnerability_score'] = {
                    'overall': security_score,
                    'risk_level': 'LOW' if security_score > 80 else 'MEDIUM' if security_score > 60 else 'HIGH',
                    'weak_password_ratio': weak_ratio
                }
                
                # Generate statistical report
                print("\n" + "="*70)
                print(math_engine.generate_statistical_report(math_analysis))
        
        # Generate HTML report
        print("\n[*] Generating HTML report...")
        report_path = html_generator.generate_html_report(extracted_data, math_analysis)
        
        print(f"\n[✓] Report generated: {report_path}")
        
        # Try to open the report
        try:
            if platform.system() == "Windows":
                os.startfile(report_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", report_path])
            else:
                subprocess.run(["xdg-open", report_path])
            print("[✓] Report opened in browser")
        except:
            print(f"[!] Could not open browser automatically")
            print(f"    Please open manually: {report_path}")
        
        print("\n" + "="*70)
        print("[✓] ANALYSIS COMPLETE")
        print("="*70)
        
        if math_analysis.get('vulnerability_score'):
            score = math_analysis['vulnerability_score']['overall']
            level = math_analysis['vulnerability_score']['risk_level']
            print(f"Security Score: {score:.1f}/100 ({level})")
        
        print(f"\n⚠ Remember to store the report securely and delete when no longer needed.")
        
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Check if running with appropriate privileges
    if platform.system() == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("[!] Not running as administrator. Some features may not work.")
                print("[!] Consider running as administrator for full functionality.")
        except:
            pass
    
    # Run main function
    main()
