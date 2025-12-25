"""
================================================================================
                 ULTIMATE PASSWORD ANALYTICS & EXTRACTION ENGINE
================================================================================
Description: Advanced tool combining password extraction with mathematical 
             analysis, statistical modeling, and professional visualization
Author: Security Analytics Team
Version: 4.0
Mathematical Methods: Laplace transforms, Probability distributions, 
                      Entropy analysis, Markov models, Fourier analysis
================================================================================
"""

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
import math
import random
import statistics
import numpy as np
from collections import Counter, defaultdict
import itertools

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
        "numpy",         # For mathematical analysis
        "matplotlib",    # For graphing and visualization
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

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("[!] NumPy not installed. Mathematical analysis will be limited.")

try:
    import matplotlib
    # Use non-interactive backend for server environments
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import cm
    import matplotlib.gridspec as gridspec
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[!] Matplotlib not installed. Graphs will not be generated.")

try:
    from scipy import stats, signal
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    print("[!] SciPy not installed. Advanced statistical analysis will be limited.")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("[!] Pandas not installed. Data analysis will be limited.")

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False
    print("[!] Jinja2 not installed. HTML templating will use basic string formatting.")

# ============================================================================
# ADDITIONAL MATH AND STATISTICS IMPORTS
# ============================================================================

try:
    import math
    import statistics
    import random
    from collections import Counter, defaultdict
    import itertools
    MATH_LIBS_AVAILABLE = True
except ImportError:
    MATH_LIBS_AVAILABLE = False
    print("[!] Some standard math libraries are not available.")

# ============================================================================
# CHECK FOR OPTIONAL ADVANCED FEATURES
# ============================================================================

def check_advanced_features():
    """Check for advanced mathematical and statistical capabilities"""
    features = {
        "numpy": HAS_NUMPY,
        "matplotlib": HAS_MATPLOTLIB,
        "scipy": HAS_SCIPY,
        "pandas": HAS_PANDAS,
        "crypto": HAS_CRYPTO,
        "win32crypt": HAS_WIN32CRYPT,
    }
    
    print("\n" + "="*70)
    print("ADVANCED FEATURES STATUS")
    print("="*70)
    
    for feature, available in features.items():
        status = "✓ AVAILABLE" if available else "✗ UNAVAILABLE"
        print(f"[{status}] {feature.upper()}")
    
    print("="*70)
    
    # Warn about missing critical features
    if not HAS_CRYPTO and platform.system() != "Windows":
        print("[!] PyCryptodome not available - decryption will be limited")
    
    if not HAS_WIN32CRYPT and platform.system() == "Windows":
        print("[!] pywin32 not available - Windows DPAPI decryption disabled")
    
    if not HAS_NUMPY:
        print("[!] NumPy not available - mathematical analysis features disabled")
    
    if not HAS_MATPLOTLIB:
        print("[!] Matplotlib not available - graphical visualizations disabled")
    
    return features

# Check features at startup
features_status = check_advanced_features()

# ============================================================================
# ADVANCED MATHEMATICAL ENGINE
# ============================================================================

class MathematicalAnalysisEngine:
    """Advanced mathematical analysis engine for password and system data"""
    
    def __init__(self):
        self.analysis_results = {}
        
    def analyze_password_entropy(self, passwords: List[str]) -> Dict:
        """Calculate entropy and statistical properties of passwords"""
        if not passwords:
            return {}
        
        entropy_values = []
        length_dist = []
        char_type_dist = {'lower': 0, 'upper': 0, 'digit': 0, 'special': 0}
        pattern_freq = Counter()
        
        for pwd in passwords:
            if not pwd or '[' in pwd:  # Skip encrypted/placeholder passwords
                continue
                
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
            
            # Calculate entropy (simplified)
            entropy = self._calculate_shannon_entropy(pwd)
            entropy_values.append(entropy)
            
            # Pattern detection
            patterns = self._detect_password_patterns(pwd)
            for pattern in patterns:
                pattern_freq[pattern] += 1
        
        # Statistical analysis
        stats = {
            'entropy_mean': np.mean(entropy_values) if entropy_values else 0,
            'entropy_std': np.std(entropy_values) if entropy_values else 0,
            'entropy_min': min(entropy_values) if entropy_values else 0,
            'entropy_max': max(entropy_values) if entropy_values else 0,
            'length_mean': np.mean(length_dist) if length_dist else 0,
            'length_std': np.std(length_dist) if length_dist else 0,
            'char_distribution': char_type_dist,
            'common_patterns': pattern_freq.most_common(10),
            'total_analyzed': len(passwords),
            'weak_passwords': len([e for e in entropy_values if e < 3.0]),
            'strong_passwords': len([e for e in entropy_values if e > 6.0])
        }
        
        # Laplace transform analysis for time-based patterns
        stats['laplace_analysis'] = self._laplace_transform_analysis(entropy_values)
        
        # Markov chain analysis
        stats['markov_analysis'] = self._markov_chain_analysis(passwords)
        
        # Fourier analysis for pattern detection
        stats['fourier_analysis'] = self._fourier_pattern_analysis(passwords)
        
        return stats
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        # Calculate frequency of each character
        prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
        
        # Calculate entropy
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    def _detect_password_patterns(self, password: str) -> List[str]:
        """Detect common password patterns"""
        patterns = []
        
        # Common patterns
        if password.isdigit():
            patterns.append("all_digits")
        elif password.isalpha():
            patterns.append("all_letters")
        elif password.isalnum() and not any(c.isalpha() for c in password):
            patterns.append("alphanumeric")
        
        # Sequential patterns
        if self._is_sequential(password):
            patterns.append("sequential")
        
        # Keyboard patterns
        if self._is_keyboard_pattern(password):
            patterns.append("keyboard_pattern")
        
        # Date patterns
        if self._is_date_pattern(password):
            patterns.append("date_pattern")
        
        # Common substitutions (e.g., p@ssw0rd)
        common_subs = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
        }
        
        return patterns
    
    def _is_sequential(self, s: str) -> bool:
        """Check if string is sequential (12345, abcde)"""
        if len(s) < 3:
            return False
        
        # Check numeric sequences
        if s.isdigit():
            nums = [int(c) for c in s]
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            if all(d == diffs[0] for d in diffs) and abs(diffs[0]) == 1:
                return True
        
        # Check alphabetical sequences
        if s.isalpha() and s.islower():
            for i in range(len(s)-1):
                if ord(s[i+1]) - ord(s[i]) != 1:
                    return False
            return True
        
        return False
    
    def _is_keyboard_pattern(self, s: str) -> bool:
        """Check for keyboard patterns (qwerty, asdfgh)"""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        s_lower = s.lower()
        for row in keyboard_rows:
            if s_lower in row or s_lower in row[::-1]:
                return True
        
        return False
    
    def _is_date_pattern(self, s: str) -> bool:
        """Check for date patterns"""
        date_patterns = [
            r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',  # DD/MM/YYYY
            r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',    # YYYY/MM/DD
            r'\d{6,8}',                         # YYMMDD or YYYYMMDD
        ]
        
        for pattern in date_patterns:
            if re.match(pattern, s):
                return True
        
        return False
    
    def _laplace_transform_analysis(self, data: List[float]) -> Dict:
        """Perform Laplace transform analysis on data patterns"""
        if not data or len(data) < 2:
            return {"error": "Insufficient data"}
        
        # Simplified Laplace-like analysis for pattern detection
        # In practice, this would use actual Laplace transforms
        n = len(data)
        
        # Calculate moments (simplified)
        mean = np.mean(data)
        variance = np.var(data)
        skewness = statistics.mean([((x - mean) ** 3) for x in data]) / (variance ** 1.5) if variance > 0 else 0
        kurtosis = statistics.mean([((x - mean) ** 4) for x in data]) / (variance ** 2) if variance > 0 else 0
        
        # Detect periodic patterns (simplified Fourier)
        if n > 10:
            try:
                # Simple autocorrelation for pattern detection
                autocorr = np.correlate(data - mean, data - mean, mode='full')
                autocorr = autocorr[autocorr.size // 2:]
                autocorr = autocorr / autocorr[0] if autocorr[0] != 0 else autocorr
            except:
                autocorr = []
        else:
            autocorr = []
        
        return {
            "data_points": n,
            "mean": float(mean),
            "variance": float(variance),
            "skewness": float(skewness),
            "kurtosis": float(kurtosis),
            "periodicity_detected": len(autocorr) > 1 and max(autocorr[1:min(10, len(autocorr))]) > 0.7,
            "distribution_type": self._classify_distribution(data)
        }
    
    def _classify_distribution(self, data: List[float]) -> str:
        """Classify the type of distribution"""
        if not data:
            return "unknown"
        
        # Simplified distribution classification
        n = len(data)
        if n < 3:
            return "insufficient_data"
        
        mean = np.mean(data)
        std = np.std(data)
        
        if std == 0:
            return "constant"
        
        # Check for normal distribution (simplified)
        skew = statistics.mean([((x - mean) ** 3) for x in data]) / (std ** 3) if std > 0 else 0
        
        if abs(skew) < 0.5:
            return "approximately_normal"
        elif skew > 0:
            return "right_skewed"
        else:
            return "left_skewed"
    
    def _markov_chain_analysis(self, passwords: List[str]) -> Dict:
        """Perform Markov chain analysis on password character transitions"""
        if not passwords:
            return {"error": "No passwords to analyze"}
        
        # Build transition matrix for character types
        transitions = {
            'L': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Lowercase
            'U': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Uppercase
            'D': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Digit
            'S': {'L': 0, 'U': 0, 'D': 0, 'S': 0},  # Special
        }
        
        total_transitions = 0
        
        for pwd in passwords:
            if not pwd or len(pwd) < 2:
                continue
            
            prev_type = self._get_char_type(pwd[0])
            
            for char in pwd[1:]:
                curr_type = self._get_char_type(char)
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
        
        # Calculate stationary distribution (simplified)
        try:
            # Build matrix for eigenvalue calculation
            matrix = np.zeros((4, 4))
            type_order = ['L', 'U', 'D', 'S']
            
            for i, from_type in enumerate(type_order):
                for j, to_type in enumerate(type_order):
                    matrix[i, j] = transition_probs[from_type][to_type]
            
            # Find eigenvector for eigenvalue 1
            eigenvalues, eigenvectors = np.linalg.eig(matrix.T)
            
            # Find index where eigenvalue is approximately 1
            idx = np.where(np.abs(eigenvalues - 1.0) < 1e-10)[0]
            
            if len(idx) > 0:
                stationary = np.real(eigenvectors[:, idx[0]])
                stationary = stationary / stationary.sum()
                stationary_dist = {type_order[i]: float(stationary[i]) for i in range(4)}
            else:
                stationary_dist = {"L": 0.25, "U": 0.25, "D": 0.25, "S": 0.25}
                
        except:
            stationary_dist = {"L": 0.25, "U": 0.25, "D": 0.25, "S": 0.25}
        
        return {
            "transition_matrix": transition_probs,
            "stationary_distribution": stationary_dist,
            "total_transitions_analyzed": total_transitions,
            "most_common_transition": self._find_most_common_transition(transitions)
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
    
    def _find_most_common_transition(self, transitions: Dict) -> str:
        """Find the most common character type transition"""
        max_count = -1
        max_transition = ""
        
        for from_type in transitions:
            for to_type in transitions[from_type]:
                count = transitions[from_type][to_type]
                if count > max_count:
                    max_count = count
                    max_transition = f"{from_type}→{to_type}"
        
        return max_transition if max_count > 0 else "none"
    
    def _fourier_pattern_analysis(self, passwords: List[str]) -> Dict:
        """Perform Fourier analysis for periodic patterns in passwords"""
        if not passwords:
            return {"error": "No passwords to analyze"}
        
        # Convert passwords to numerical sequences for analysis
        numerical_seqs = []
        
        for pwd in passwords:
            if not pwd:
                continue
            
            # Convert characters to ASCII values
            seq = [ord(c) for c in pwd[:50]]  # Limit length for analysis
            numerical_seqs.append(seq)
        
        if not numerical_seqs:
            return {"error": "No valid password sequences"}
        
        # Analyze each sequence
        all_fft_magnitudes = []
        dominant_frequencies = []
        
        for seq in numerical_seqs:
            if len(seq) < 4:  # Need minimum length for FFT
                continue
            
            try:
                # Perform FFT
                fft_result = np.fft.fft(seq)
                fft_magnitude = np.abs(fft_result)
                
                # Store magnitudes (skip DC component)
                all_fft_magnitudes.extend(fft_magnitude[1:min(10, len(fft_magnitude))])
                
                # Find dominant frequency (excluding DC)
                if len(fft_magnitude) > 1:
                    dominant_idx = np.argmax(fft_magnitude[1:]) + 1
                    dominant_freq = dominant_idx / len(seq)
                    dominant_frequencies.append(dominant_freq)
                    
            except:
                continue
        
        # Analyze results
        if not all_fft_magnitudes:
            return {"error": "FFT analysis failed"}
        
        return {
            "fft_magnitude_mean": float(np.mean(all_fft_magnitudes)),
            "fft_magnitude_std": float(np.std(all_fft_magnitudes)),
            "dominant_freq_mean": float(np.mean(dominant_frequencies)) if dominant_frequencies else 0,
            "periodic_patterns_detected": len([f for f in dominant_frequencies if f > 0.1]) > len(dominant_frequencies) * 0.5,
            "sequences_analyzed": len(numerical_seqs),
            "analysis_technique": "Fast Fourier Transform (FFT)"
        }
    
    def analyze_system_data(self, system_data: Dict) -> Dict:
        """Perform comprehensive statistical analysis on system data"""
        analysis = {}
        
        # Browser password analysis
        if 'browser_passwords' in system_data:
            passwords = [p.get('password', '') for p in system_data['browser_passwords']]
            valid_passwords = [p for p in passwords if p and '[' not in p]
            
            analysis['password_stats'] = self.analyze_password_entropy(valid_passwords)
            
            # URL/domain analysis
            urls = [p.get('url', '') for p in system_data['browser_passwords'] if p.get('url')]
            if urls:
                analysis['domain_stats'] = self._analyze_domains(urls)
        
        # WiFi network analysis
        if 'wifi_passwords' in system_data:
            wifi_data = system_data['wifi_passwords']
            if wifi_data:
                analysis['wifi_stats'] = self._analyze_wifi_networks(wifi_data)
        
        # System vulnerability scoring
        analysis['vulnerability_score'] = self._calculate_vulnerability_score(system_data)
        
        # Risk assessment using probability models
        analysis['risk_assessment'] = self._probability_risk_assessment(system_data)
        
        return analysis
    
    def _analyze_domains(self, urls: List[str]) -> Dict:
        """Analyze domain patterns and frequencies"""
        domains = []
        
        for url in urls:
            try:
                # Extract domain from URL
                if '://' in url:
                    domain = url.split('://')[1].split('/')[0]
                else:
                    domain = url.split('/')[0]
                
                # Remove port if present
                domain = domain.split(':')[0]
                domains.append(domain)
            except:
                continue
        
        if not domains:
            return {"error": "No valid domains found"}
        
        # Count domain frequencies
        domain_counts = Counter(domains)
        
        # Categorize by TLD
        tld_counts = Counter()
        for domain in domains:
            parts = domain.split('.')
            if len(parts) > 1:
                tld = parts[-1]
                tld_counts[tld] += 1
        
        return {
            "unique_domains": len(domain_counts),
            "total_domains": len(domains),
            "most_common_domains": domain_counts.most_common(10),
            "tld_distribution": tld_counts.most_common(),
            "entropy_of_domains": self._calculate_shannon_entropy(''.join(domains))
        }
    
    def _analyze_wifi_networks(self, wifi_data: List[Dict]) -> Dict:
        """Analyze WiFi network security"""
        if not wifi_data:
            return {"error": "No WiFi data"}
        
        security_types = Counter()
        password_lengths = []
        open_networks = 0
        secured_networks = 0
        
        for wifi in wifi_data:
            security = wifi.get('security', '').lower()
            password = wifi.get('password', '')
            
            security_types[security] += 1
            
            if 'open' in security or 'none' in security:
                open_networks += 1
            else:
                secured_networks += 1
            
            if password and password.lower() not in ['not found', '[encrypted]', '']:
                password_lengths.append(len(password))
        
        # Calculate security metrics
        total_networks = len(wifi_data)
        security_ratio = secured_networks / total_networks if total_networks > 0 else 0
        
        return {
            "total_networks": total_networks,
            "open_networks": open_networks,
            "secured_networks": secured_networks,
            "security_ratio": security_ratio,
            "security_distribution": dict(security_types.most_common()),
            "avg_password_length": np.mean(password_lengths) if password_lengths else 0,
            "security_risk_score": (open_networks / total_networks) * 100 if total_networks > 0 else 100
        }
    
    def _calculate_vulnerability_score(self, data: Dict) -> Dict:
        """Calculate system vulnerability score using multiple factors"""
        scores = {
            'password_strength': 0,
            'wifi_security': 0,
            'system_exposure': 0,
            'overall': 0
        }
        
        weights = {
            'password_strength': 0.4,
            'wifi_security': 0.3,
            'system_exposure': 0.3
        }
        
        # Password strength scoring
        if 'browser_passwords' in data:
            passwords = [p.get('password', '') for p in data['browser_passwords']]
            valid_passwords = [p for p in passwords if p and '[' not in p]
            
            if valid_passwords:
                entropy_stats = self.analyze_password_entropy(valid_passwords)
                weak_ratio = entropy_stats.get('weak_passwords', 0) / len(valid_passwords) if valid_passwords else 1
                scores['password_strength'] = (1 - weak_ratio) * 100
            else:
                scores['password_strength'] = 50  # Neutral if no passwords
        
        # WiFi security scoring
        if 'wifi_passwords' in data and data['wifi_passwords']:
            wifi_stats = self._analyze_wifi_networks(data['wifi_passwords'])
            scores['wifi_security'] = wifi_stats.get('security_ratio', 0) * 100
        
        # System exposure scoring (simplified)
        exposure_factors = 0
        if 'system_credentials' in data and data['system_credentials']:
            exposure_factors += 0.3
        
        if 'email_clients' in data and data['email_clients']:
            exposure_factors += 0.3
        
        if 'ftp_clients' in data and data['ftp_clients']:
            exposure_factors += 0.2
        
        if 'database_clients' in data and data['database_clients']:
            exposure_factors += 0.2
        
        scores['system_exposure'] = (1 - min(exposure_factors, 1)) * 100
        
        # Calculate overall score
        overall = sum(scores[factor] * weights[factor] for factor in weights)
        scores['overall'] = overall
        
        # Risk classification
        if overall >= 80:
            risk_level = "LOW"
        elif overall >= 60:
            risk_level = "MODERATE"
        elif overall >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        scores['risk_level'] = risk_level
        scores['recommendations'] = self._generate_recommendations(scores)
        
        return scores
    
    def _probability_risk_assessment(self, data: Dict) -> Dict:
        """Perform probability-based risk assessment"""
        # Initialize probabilities
        probabilities = {
            'password_compromise': 0.1,  # Base probability
            'wifi_attack': 0.05,
            'system_breach': 0.02,
            'data_exfiltration': 0.01
        }
        
        # Adjust based on data
        if 'browser_passwords' in data:
            passwords = data['browser_passwords']
            if passwords:
                weak_count = sum(1 for p in passwords if len(p.get('password', '')) < 8)
                weak_ratio = weak_count / len(passwords)
                probabilities['password_compromise'] += weak_ratio * 0.3
        
        if 'wifi_passwords' in data:
            wifi_networks = data['wifi_passwords']
            open_count = sum(1 for w in wifi_networks if 'open' in str(w.get('security', '')).lower())
            if wifi_networks:
                open_ratio = open_count / len(wifi_networks)
                probabilities['wifi_attack'] += open_ratio * 0.4
        
        # Calculate combined risk using probability theory
        # P(at least one event) = 1 - P(no events)
        p_no_events = 1
        for event, prob in probabilities.items():
            p_no_events *= (1 - min(prob, 0.99))
        
        overall_risk = 1 - p_no_events
        
        # Bayesian update based on evidence (simplified)
        evidence_factors = 0
        if 'system_credentials' in data and data['system_credentials']:
            evidence_factors += 0.1
        if 'email_clients' in data and data['email_clients']:
            evidence_factors += 0.15
        
        updated_risk = overall_risk * (1 + evidence_factors)
        
        return {
            'individual_probabilities': probabilities,
            'overall_risk_probability': min(updated_risk, 0.99),
            'risk_interpretation': self._interpret_risk_probability(updated_risk),
            'expected_loss_impact': self._calculate_expected_loss(probabilities)
        }
    
    def _interpret_risk_probability(self, probability: float) -> str:
        """Interpret risk probability level"""
        if probability < 0.1:
            return "Negligible risk"
        elif probability < 0.3:
            return "Low risk"
        elif probability < 0.5:
            return "Moderate risk"
        elif probability < 0.7:
            return "High risk"
        else:
            return "Critical risk"
    
    def _calculate_expected_loss(self, probabilities: Dict) -> float:
        """Calculate expected loss using probability * impact"""
        impacts = {
            'password_compromise': 50,
            'wifi_attack': 30,
            'system_breach': 100,
            'data_exfiltration': 150
        }
        
        expected_loss = 0
        for event, prob in probabilities.items():
            impact = impacts.get(event, 25)
            expected_loss += prob * impact
        
        return expected_loss
    
    def _generate_recommendations(self, scores: Dict) -> List[str]:
        """Generate security recommendations based on scores"""
        recommendations = []
        
        if scores['password_strength'] < 70:
            recommendations.append("Implement stronger password policies")
            recommendations.append("Enable two-factor authentication where possible")
            recommendations.append("Use a password manager")
        
        if scores['wifi_security'] < 80:
            recommendations.append("Secure WiFi networks with WPA3 encryption")
            recommendations.append("Change default router passwords")
            recommendations.append("Disable WPS if not needed")
        
        if scores['system_exposure'] < 60:
            recommendations.append("Review and secure system credentials")
            recommendations.append("Regularly update software and systems")
            recommendations.append("Implement network segmentation")
        
        if scores['overall'] < 60:
            recommendations.append("Conduct comprehensive security audit")
            recommendations.append("Implement security awareness training")
            recommendations.append("Develop incident response plan")
        
        return recommendations

# ============================================================================
# PROFESSIONAL HTML REPORT GENERATOR WITH HACKER DESIGN
# ============================================================================

class ProfessionalHTMLReportGenerator:
    """Generate professional HTML reports with hacker aesthetic"""
    
    def __init__(self):
        self.html_content = ""
        self.stats = {}
        self.math_analysis = {}
        
    def generate_html_report(self, extracted_data: Dict, math_analysis: Dict) -> str:
        """Generate comprehensive HTML report"""
        self.stats = self._calculate_statistics(extracted_data)
        self.math_analysis = math_analysis
        
        downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(downloads_path, f'Security_Analytics_Report_{timestamp}.html')
        
        # Generate HTML content
        html = self._create_hacker_html_template(extracted_data)
        
        # Write to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_path
    
    def _calculate_statistics(self, data: Dict) -> Dict:
        """Calculate comprehensive statistics"""
        stats = {
            "total_passwords": len(data.get("browser_passwords", [])),
            "decrypted_passwords": len([p for p in data.get("browser_passwords", []) 
                                      if p.get('password') and '[' not in p.get('password', '')]),
            "unique_browsers": len(set(p.get('browser', '') for p in data.get("browser_passwords", []))),
            "wifi_networks": len(data.get("wifi_passwords", [])),
            "system_credentials": len(data.get("system_credentials", [])),
            "email_accounts": len(data.get("email_clients", [])),
            "unique_domains": len(set(p.get('url', '').split('/')[2] if '//' in p.get('url', '') else ''
                                    for p in data.get("browser_passwords", []) if p.get('url'))),
            "password_strength_score": 0,
            "security_risk_score": 0
        }
        
        return stats
    
    def _create_hacker_html_template(self, data: Dict) -> str:
        """Create hacker-themed HTML report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = getpass.getuser()
        system_info = f"{platform.system()} {platform.release()}"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⎝⧹⎠ SECURITY ANALYTICS REPORT ⎝⧸⎠</title>
    <style>
        /* Hacker Theme CSS */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background-color: #0a0a0a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.6;
            padding: 20px;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 255, 0, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 90% 80%, rgba(0, 255, 0, 0.03) 0%, transparent 20%);
            position: relative;
            overflow-x: hidden;
        }}
        
        /* Matrix rain effect container */
        #matrix {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            opacity: 0.1;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }}
        
        /* Header Styles */
        .header {{
            background: linear-gradient(90deg, #001100, #003300, #001100);
            padding: 30px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent 30%, rgba(0, 255, 0, 0.1) 50%, transparent 70%);
            animation: scan 8s linear infinite;
        }}
        
        @keyframes scan {{
            0% {{ transform: translateY(-100%); }}
            100% {{ transform: translateY(100%); }}
        }}
        
        .header h1 {{
            font-size: 2.5em;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 10px;
            letter-spacing: 2px;
            position: relative;
        }}
        
        .header h1::after {{
            content: '█';
            animation: blink 1s infinite;
        }}
        
        @keyframes blink {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0; }}
        }}
        
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .meta-item {{
            background: rgba(0, 32, 0, 0.5);
            padding: 10px;
            border-left: 3px solid #00ff00;
        }}
        
        /* Section Styles */
        .section {{
            background: rgba(0, 16, 0, 0.7);
            border: 1px solid #00aa00;
            border-radius: 5px;
            padding: 25px;
            margin-bottom: 30px;
            position: relative;
            transition: all 0.3s ease;
        }}
        
        .section:hover {{
            border-color: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
        }}
        
        .section-title {{
            color: #00ff00;
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #00aa00;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title::before {{
            content: '>>>';
            color: #00ff00;
        }}
        
        /* Dashboard Grid */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(145deg, #001a00, #000d00);
            border: 1px solid #008800;
            border-radius: 5px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, #00ff00, transparent);
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: #00ff00;
            box-shadow: 0 5px 15px rgba(0, 255, 0, 0.2);
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff00;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: #00aa00;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Progress Bars */
        .progress-container {{
            margin: 20px 0;
        }}
        
        .progress-label {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
            color: #00aa00;
        }}
        
        .progress-bar {{
            height: 10px;
            background: #002200;
            border-radius: 5px;
            overflow: hidden;
            position: relative;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00aa00, #00ff00);
            border-radius: 5px;
            position: relative;
            transition: width 1s ease;
        }}
        
        .progress-fill::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, 
                transparent 0%, 
                rgba(255, 255, 255, 0.2) 50%, 
                transparent 100%);
            animation: shimmer 2s infinite;
        }}
        
        @keyframes shimmer {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}
        
        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        .data-table th {{
            background: rgba(0, 50, 0, 0.7);
            color: #00ff00;
            padding: 12px;
            text-align: left;
            border: 1px solid #00aa00;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .data-table td {{
            padding: 10px 12px;
            border: 1px solid #004400;
            color: #00cc00;
        }}
        
        .data-table tr:nth-child(even) {{
            background: rgba(0, 32, 0, 0.3);
        }}
        
        .data-table tr:hover {{
            background: rgba(0, 64, 0, 0.5);
            color: #00ff00;
        }}
        
        /* Matrix Visualization */
        .matrix-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin: 20px 0;
        }}
        
        .matrix-cell {{
            background: rgba(0, 32, 0, 0.5);
            border: 1px solid #004400;
            padding: 10px;
            text-align: center;
            font-family: monospace;
            transition: all 0.3s ease;
        }}
        
        .matrix-cell:hover {{
            background: rgba(0, 64, 0, 0.7);
            border-color: #00ff00;
            transform: scale(1.05);
        }}
        
        /* Risk Indicators */
        .risk-indicator {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .risk-low {{
            background: rgba(0, 64, 0, 0.7);
            color: #00ff00;
            border: 1px solid #00ff00;
        }}
        
        .risk-medium {{
            background: rgba(100, 100, 0, 0.7);
            color: #ffff00;
            border: 1px solid #ffff00;
        }}
        
        .risk-high {{
            background: rgba(100, 50, 0, 0.7);
            color: #ff9900;
            border: 1px solid #ff9900;
        }}
        
        .risk-critical {{
            background: rgba(100, 0, 0, 0.7);
            color: #ff0000;
            border: 1px solid #ff0000;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        /* Console Output */
        .console {{
            background: #001100;
            border: 1px solid #00aa00;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.4;
            max-height: 300px;
            overflow-y: auto;
        }}
        
        .console-line {{
            margin-bottom: 5px;
            color: #00cc00;
        }}
        
        .console-line::before {{
            content: '$ ';
            color: #00ff00;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px;
            margin-top: 50px;
            border-top: 1px solid #004400;
            color: #00aa00;
            font-size: 0.9em;
        }}
        
        .warning {{
            color: #ff0000;
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff0000;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            animation: glow 2s infinite alternate;
        }}
        
        @keyframes glow {{
            from {{ box-shadow: 0 0 5px rgba(255, 0, 0, 0.5); }}
            to {{ box-shadow: 0 0 15px rgba(255, 0, 0, 0.8); }}
        }}
        
        /* Responsive Design */
        @media (max-width: 768px) {{
            .dashboard {{
                grid-template-columns: 1fr;
            }}
            
            .metadata {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .section {{
                padding: 15px;
            }}
        }}
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {{
            width: 10px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #001100;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: #00aa00;
            border-radius: 5px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: #00ff00;
        }}
    </style>
</head>
<body>
    <!-- Matrix Rain Effect -->
    <div id="matrix"></div>
    
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>⎝⧹⎠ SECURITY ANALYTICS REPORT ⎝⧸⎠</h1>
            <div class="console">
                <div class="console-line">INITIALIZING SECURITY SCAN...</div>
                <div class="console-line">SYSTEM: {system_info}</div>
                <div class="console-line">USER: {username}</div>
                <div class="console-line">TIMESTAMP: {timestamp}</div>
                <div class="console-line">STATUS: ANALYSIS COMPLETE</div>
            </div>
            
            <div class="metadata">
                <div class="meta-item">
                    <div class="stat-label">Total Passwords</div>
                    <div class="stat-value">{self.stats.get('total_passwords', 0)}</div>
                </div>
                <div class="meta-item">
                    <div class="stat-label">WiFi Networks</div>
                    <div class="stat-value">{self.stats.get('wifi_networks', 0)}</div>
                </div>
                <div class="meta-item">
                    <div class="stat-label">System Credentials</div>
                    <div class="stat-value">{self.stats.get('system_credentials', 0)}</div>
                </div>
                <div class="meta-item">
                    <div class="stat-label">Unique Domains</div>
                    <div class="stat-value">{self.stats.get('unique_domains', 0)}</div>
                </div>
            </div>
        </div>
        
        <div class="warning">
            ⚠ WARNING: This report contains sensitive information. Handle with extreme caution.
            Store securely and delete when no longer needed.
        </div>
        
        <!-- Dashboard -->
        <div class="section">
            <div class="section-title">DASHBOARD OVERVIEW</div>
            <div class="dashboard">
                {self._generate_dashboard_cards()}
            </div>
        </div>
        
        <!-- Mathematical Analysis -->
        <div class="section">
            <div class="section-title">MATHEMATICAL ANALYSIS</div>
            {self._generate_math_analysis_section()}
        </div>
        
        <!-- Password Analysis -->
        <div class="section">
            <div class="section-title">PASSWORD STATISTICS</div>
            {self._generate_password_analysis(data)}
        </div>
        
        <!-- WiFi Analysis -->
        <div class="section">
            <div class="section-title">NETWORK ANALYSIS</div>
            {self._generate_wifi_analysis(data)}
        </div>
        
        <!-- Risk Assessment -->
        <div class="section">
            <div class="section-title">RISK ASSESSMENT</div>
            {self._generate_risk_assessment()}
        </div>
        
        <!-- System Credentials -->
        <div class="section">
            <div class="section-title">SYSTEM DATA</div>
            {self._generate_system_data_section(data)}
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <div class="section-title">SECURITY RECOMMENDATIONS</div>
            {self._generate_recommendations_section()}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <div>GENERATED BY: SECURITY ANALYTICS ENGINE v4.0</div>
            <div>TIMESTAMP: {timestamp}</div>
            <div style="margin-top: 10px; color: #008800;">
                ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯
            </div>
        </div>
    </div>
    
    <script>
        // Matrix rain effect
        function createMatrixEffect() {{
            const matrix = document.getElementById('matrix');
            const chars = "01";
            const fontSize = 14;
            const columns = Math.floor(window.innerWidth / fontSize);
            
            const drops = Array(columns).fill(1);
            
            function draw() {{
                const ctx = matrix.getContext('2d');
                matrix.width = window.innerWidth;
                matrix.height = window.innerHeight;
                
                ctx.fillStyle = 'rgba(0, 16, 0, 0.05)';
                ctx.fillRect(0, 0, matrix.width, matrix.height);
                
                ctx.fillStyle = '#00ff00';
                ctx.font = fontSize + 'px monospace';
                
                for (let i = 0; i < drops.length; i++) {{
                    const text = chars[Math.floor(Math.random() * chars.length)];
                    const x = i * fontSize;
                    const y = drops[i] * fontSize;
                    
                    ctx.fillText(text, x, y);
                    
                    if (y > matrix.height && Math.random() > 0.975) {{
                        drops[i] = 0;
                    }}
                    
                    drops[i]++;
                }}
            }}
            
            // Create canvas if it doesn't exist
            if (!matrix.getContext) {{
                matrix.innerHTML = '<canvas></canvas>';
                matrix.firstChild.width = window.innerWidth;
                matrix.firstChild.height = window.innerHeight;
                matrix.firstChild.style.position = 'fixed';
                matrix.firstChild.style.top = '0';
                matrix.firstChild.style.left = '0';
                matrix.firstChild.style.zIndex = '-1';
            }}
            
            setInterval(draw, 35);
        }}
        
        // Initialize when page loads
        window.addEventListener('load', function() {{
            createMatrixEffect();
            
            // Animate progress bars
            document.querySelectorAll('.progress-fill').forEach(bar => {{
                const width = bar.style.width;
                bar.style.width = '0';
                setTimeout(() => {{
                    bar.style.width = width;
                }}, 100);
            }});
            
            // Add typing effect to console
            const consoleLines = document.querySelectorAll('.console-line');
            consoleLines.forEach((line, index) => {{
                const text = line.textContent;
                line.textContent = '';
                let i = 0;
                
                setTimeout(() => {{
                    const typeWriter = () => {{
                        if (i < text.length) {{
                            line.textContent += text.charAt(i);
                            i++;
                            setTimeout(typeWriter, 50);
                        }}
                    }};
                    typeWriter();
                }}, index * 500);
            }});
        }});
        
        // Update risk indicators with animation
        document.querySelectorAll('.risk-indicator').forEach(indicator => {{
            indicator.addEventListener('mouseenter', function() {{
                this.style.transform = 'scale(1.1)';
            }});
            
            indicator.addEventListener('mouseleave', function() {{
                this.style.transform = 'scale(1)';
            }});
        }});
        
        // Table row highlighting
        document.querySelectorAll('.data-table tr').forEach(row => {{
            row.addEventListener('click', function() {{
                this.classList.toggle('selected');
            }});
        }});
    </script>
</body>
</html>"""
        return html
    
    def _generate_dashboard_cards(self) -> str:
        """Generate dashboard cards with statistics"""
        password_strength = self.math_analysis.get('password_stats', {}).get('entropy_mean', 0) * 10
        vulnerability_score = self.math_analysis.get('vulnerability_score', {}).get('overall', 50)
        risk_probability = self.math_analysis.get('risk_assessment', {}).get('overall_risk_probability', 0.5) * 100
        
        cards = f"""
            <div class="stat-card">
                <div class="stat-label">Password Strength</div>
                <div class="stat-value">{password_strength:.1f}%</div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {password_strength}%"></div>
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Security Score</div>
                <div class="stat-value">{vulnerability_score:.0f}/100</div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {vulnerability_score}%"></div>
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Risk Probability</div>
                <div class="stat-value">{risk_probability:.1f}%</div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {risk_probability}%"></div>
                    </div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Data Points</div>
                <div class="stat-value">{self.stats.get('total_passwords', 0) + self.stats.get('wifi_networks', 0)}</div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {min(100, (self.stats.get('total_passwords', 0) + self.stats.get('wifi_networks', 0)) / 10)}%"></div>
                    </div>
                </div>
            </div>
        """
        
        return cards
    
    def _generate_math_analysis_section(self) -> str:
        """Generate mathematical analysis section"""
        if not self.math_analysis:
            return "<div class='console'>No mathematical analysis data available</div>"
        
        password_stats = self.math_analysis.get('password_stats', {})
        risk_assessment = self.math_analysis.get('risk_assessment', {})
        vulnerability = self.math_analysis.get('vulnerability_score', {})
        
        html = f"""
            <div class="console">
                <div class="console-line">ENTROPY ANALYSIS: Mean={password_stats.get('entropy_mean', 0):.2f} bits</div>
                <div class="console-line">DISTRIBUTION: {password_stats.get('laplace_analysis', {{}}).get('distribution_type', 'Unknown')}</div>
                <div class="console-line">WEAK PASSWORDS: {password_stats.get('weak_passwords', 0)} detected</div>
                <div class="console-line">MARKOV ANALYSIS: {password_stats.get('markov_analysis', {{}}).get('total_transitions_analyzed', 0)} transitions</div>
                <div class="console-line">FOURIER ANALYSIS: Periodic patterns detected: {password_stats.get('fourier_analysis', {{}}).get('periodic_patterns_detected', False)}</div>
            </div>
            
            <div class="matrix-grid">
                <div class="matrix-cell">
                    <div>Shannon Entropy</div>
                    <div class="stat-value">{password_stats.get('entropy_mean', 0):.2f}</div>
                </div>
                <div class="matrix-cell">
                    <div>Skewness</div>
                    <div class="stat-value">{password_stats.get('laplace_analysis', {{}}).get('skewness', 0):.2f}</div>
                </div>
                <div class="matrix-cell">
                    <div>Kurtosis</div>
                    <div class="stat-value">{password_stats.get('laplace_analysis', {{}}).get('kurtosis', 0):.2f}</div>
                </div>
                <div class="matrix-cell">
                    <div>Risk Probability</div>
                    <div class="stat-value">{risk_assessment.get('overall_risk_probability', 0) * 100:.1f}%</div>
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <h3 style="color: #00ff00; margin-bottom: 10px;">Vulnerability Analysis</h3>
                <div class="progress-container">
                    <div class="progress-label">
                        <span>Overall Security</span>
                        <span>{vulnerability.get('overall', 0):.1f}/100</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {vulnerability.get('overall', 0)}%"></div>
                    </div>
                </div>
                
                <div class="progress-container">
                    <div class="progress-label">
                        <span>Password Strength</span>
                        <span>{vulnerability.get('password_strength', 0):.1f}/100</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {vulnerability.get('password_strength', 0)}%"></div>
                    </div>
                </div>
                
                <div class="progress-container">
                    <div class="progress-label">
                        <span>WiFi Security</span>
                        <span>{vulnerability.get('wifi_security', 0):.1f}/100</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {vulnerability.get('wifi_security', 0)}%"></div>
                    </div>
                </div>
            </div>
        """
        
        return html
    
    def _generate_password_analysis(self, data: Dict) -> str:
        """Generate password analysis section"""
        browser_passwords = data.get('browser_passwords', [])
        
        if not browser_passwords:
            return "<div class='console'>No password data available</div>"
        
        # Get top 10 passwords for display
        display_passwords = browser_passwords[:10]
        
        html = f"""
            <div class="console">
                <div class="console-line">TOTAL PASSWORDS ANALYZED: {len(browser_passwords)}</div>
                <div class="console-line">DECRYPTED: {len([p for p in browser_passwords if p.get('password') and '[' not in p.get('password', '')])}</div>
                <div class="console-line">ENCRYPTED: {len([p for p in browser_passwords if not p.get('password') or '[' in p.get('password', '')])}</div>
            </div>
            
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Browser</th>
                        <th>URL</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for pwd in display_passwords:
            password = pwd.get('password', '')
            if len(password) > 20:
                password = password[:20] + '...'
            
            status = "DECRYPTED" if password and '[' not in password else "ENCRYPTED"
            status_class = "risk-low" if status == "DECRYPTED" else "risk-medium"
            
            html += f"""
                    <tr>
                        <td>{pwd.get('browser', 'N/A')}</td>
                        <td>{pwd.get('url', '')[:30] + ('...' if len(pwd.get('url', '')) > 30 else '')}</td>
                        <td>{pwd.get('username', '')[:20] + ('...' if len(pwd.get('username', '')) > 20 else '')}</td>
                        <td>{password}</td>
                        <td><span class="risk-indicator {status_class}">{status}</span></td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        """
        
        return html
    
    def _generate_wifi_analysis(self, data: Dict) -> str:
        """Generate WiFi analysis section"""
        wifi_data = data.get('wifi_passwords', [])
        
        if not wifi_data:
            return "<div class='console'>No WiFi data available</div>"
        
        html = f"""
            <div class="console">
                <div class="console-line">WIFI NETWORKS DETECTED: {len(wifi_data)}</div>
                <div class="console-line">SECURED NETWORKS: {len([w for w in wifi_data if 'open' not in str(w.get('security', '')).lower()])}</div>
                <div class="console-line">OPEN NETWORKS: {len([w for w in wifi_data if 'open' in str(w.get('security', '')).lower()])}</div>
            </div>
            
            <table class="data-table">
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>Security</th>
                        <th>Password</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for wifi in wifi_data[:10]:  # Show top 10
            ssid = wifi.get('ssid', 'Unknown')
            security = wifi.get('security', 'Unknown')
            password = wifi.get('password', 'Not found')
            
            # Determine risk level
            if 'open' in security.lower() or 'none' in security.lower():
                risk_level = "CRITICAL"
                risk_class = "risk-critical"
            elif 'wpa3' in security.lower():
                risk_level = "LOW"
                risk_class = "risk-low"
            elif 'wpa2' in security.lower():
                risk_level = "MEDIUM"
                risk_class = "risk-medium"
            else:
                risk_level = "HIGH"
                risk_class = "risk-high"
            
            html += f"""
                    <tr>
                        <td>{ssid[:25] + ('...' if len(ssid) > 25 else '')}</td>
                        <td>{security}</td>
                        <td>{'*' * min(10, len(password)) if password and password.lower() != 'not found' else 'Not found'}</td>
                        <td><span class="risk-indicator {risk_class}">{risk_level}</span></td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        """
        
        return html
    
    def _generate_risk_assessment(self) -> str:
        """Generate risk assessment section"""
        if not self.math_analysis:
            return "<div class='console'>No risk assessment data available</div>"
        
        vulnerability = self.math_analysis.get('vulnerability_score', {})
        risk_assessment = self.math_analysis.get('risk_assessment', {})
        
        risk_level = vulnerability.get('risk_level', 'UNKNOWN')
        risk_class = f"risk-{risk_level.lower()}" if risk_level != 'UNKNOWN' else "risk-medium"
        
        html = f"""
            <div class="console">
                <div class="console-line">OVERALL RISK LEVEL: {risk_level}</div>
                <div class="console-line">VULNERABILITY SCORE: {vulnerability.get('overall', 0):.1f}/100</div>
                <div class="console-line">RISK PROBABILITY: {risk_assessment.get('overall_risk_probability', 0) * 100:.1f}%</div>
                <div class="console-line">EXPECTED LOSS IMPACT: ${risk_assessment.get('expected_loss_impact', 0):.1f}</div>
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
                <div class="risk-indicator {risk_class}" style="font-size: 1.5em; padding: 15px 30px;">
                    {risk_level} RISK
                </div>
            </div>
            
            <div class="matrix-grid">
        """
        
        # Add probability indicators
        probabilities = risk_assessment.get('individual_probabilities', {})
        for event, prob in probabilities.items():
            prob_percent = prob * 100
            html += f"""
                <div class="matrix-cell">
                    <div>{event.replace('_', ' ').title()}</div>
                    <div class="stat-value">{prob_percent:.1f}%</div>
                </div>
            """
        
        html += """
            </div>
        """
        
        return html
    
    def _generate_system_data_section(self, data: Dict) -> str:
        """Generate system data section"""
        html = "<div class='matrix-grid'>"
        
        # System credentials
        sys_creds = data.get('system_credentials', [])
        if sys_creds:
            html += f"""
                <div class="matrix-cell">
                    <div>System Credentials</div>
                    <div class="stat-value">{len(sys_creds)}</div>
                </div>
            """
        
        # Email clients
        email_clients = data.get('email_clients', [])
        if email_clients:
            html += f"""
                <div class="matrix-cell">
                    <div>Email Accounts</div>
                    <div class="stat-value">{len(email_clients)}</div>
                </div>
            """
        
        # FTP clients
        ftp_clients = data.get('ftp_clients', [])
        if ftp_clients:
            html += f"""
                <div class="matrix-cell">
                    <div>FTP Connections</div>
                    <div class="stat-value">{len(ftp_clients)}</div>
                </div>
            """
        
        # Database clients
        db_clients = data.get('database_clients', [])
        if db_clients:
            html += f"""
                <div class="matrix-cell">
                    <div>Database Connections</div>
                    <div class="stat-value">{len(db_clients)}</div>
                </div>
            """
        
        # VPN configs
        vpn_configs = data.get('vpn_configs', [])
        if vpn_configs:
            html += f"""
                <div class="matrix-cell">
                    <div>VPN Configurations</div>
                    <div class="stat-value">{len(vpn_configs)}</div>
                </div>
            """
        
        html += "</div>"
        
        return html
    
    def _generate_recommendations_section(self) -> str:
        """Generate recommendations section"""
        if not self.math_analysis:
            return "<div class='console'>No recommendations available</div>"
        
        recommendations = self.math_analysis.get('vulnerability_score', {}).get('recommendations', [])
        
        if not recommendations:
            return "<div class='console'>System security appears adequate. Continue regular monitoring.</div>"
        
        html = "<div class='console'>"
        
        for i, rec in enumerate(recommendations, 1):
            html += f"""
                <div class="console-line">[{i:02d}] {rec}</div>
            """
        
        html += "</div>"
        
        return html

# ============================================================================
# ENHANCED MAIN EXECUTION WITH MATHEMATICAL ANALYSIS
# ============================================================================

def main():
    """Enhanced main execution with mathematical analysis"""
    try:
        print(f"\n{'='*80}")
        print("                 SECURITY ANALYTICS ENGINE v4.0")
        print("                    WITH MATHEMATICAL ANALYSIS")
        print(f"{'='*80}")
        
        # Get user confirmation
        print("\n⚠  WARNING: This tool performs security analysis.")
        print("   Use only on systems you own or have explicit permission to test.")
        
        response = input("\nDo you understand and accept responsibility? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Operation cancelled.")
            return
        
        # Initialize components
        extractor = ComprehensivePasswordExtractor()
        math_engine = MathematicalAnalysisEngine()
        html_generator = ProfessionalHTMLReportGenerator()
        
        print("\n[*] Starting comprehensive security analysis...")
        
        # Extract data
        extracted_data = extractor.extract_all_passwords()
        
        # Perform mathematical analysis
        print("\n[*] Performing mathematical analysis...")
        math_analysis = math_engine.analyze_system_data(extracted_data)
        
        # Generate HTML report
        print("\n[*] Generating professional report...")
        report_path = html_generator.generate_html_report(extracted_data, math_analysis)
        
        print(f"\n[✓] Report generated: {report_path}")
        
        # Open report in browser
        try:
            if platform.system() == "Windows":
                os.startfile(report_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", report_path])
            else:
                subprocess.run(["xdg-open", report_path])
            print("[✓] Report opened in browser")
        except Exception as e:
            print(f"[!] Could not open browser: {e}")
            print(f"    Please open manually: {report_path}")
        
        # Print summary
        print(f"\n{'='*80}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*80}")
        
        if 'vulnerability_score' in math_analysis:
            score = math_analysis['vulnerability_score']['overall']
            level = math_analysis['vulnerability_score']['risk_level']
            print(f"Security Score: {score:.1f}/100 ({level})")
        
        if 'risk_assessment' in math_analysis:
            risk_prob = math_analysis['risk_assessment']['overall_risk_probability'] * 100
            print(f"Risk Probability: {risk_prob:.1f}%")
        
        print(f"\n⚠  Remember to store the report securely and delete when no longer needed.")
        
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        import traceback
        traceback.print_exc()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Check for required packages
    try:
        import numpy as np
        HAS_NUMPY = True
    except ImportError:
        print("[!] NumPy is required for mathematical analysis.")
        print("    Install with: pip install numpy")
        HAS_NUMPY = False
    
    if HAS_NUMPY:
        main()
    else:
        print("[!] Mathematical analysis features disabled.")
        print("    Install NumPy and restart the tool.")
