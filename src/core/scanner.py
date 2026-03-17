"""
Core Scanner Module

This module contains the main SecurityScanner class that orchestrates
the vulnerability detection process.
"""

import os
from pathlib import Path
from typing import List, Union
from dataclasses import dataclass, field
from datetime import datetime

from .config import ScannerConfig
from patterns.pattern_registry import PatternRegistry
from mappers.masvs_mapper import MasvsMapper


@dataclass
class Finding:
    """Represents a single security finding."""
    vulnerability_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    file_path: str
    line_number: int
    code_snippet: str
    masvs_category: str
    masvs_control: str
    remediation: str
    cwe_id: str = ""
    confidence: str = "high"  # high, medium, low
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'masvs_category': self.masvs_category,
            'masvs_control': self.masvs_control,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'confidence': self.confidence
        }


@dataclass
class ScanResults:
    """Container for scan results."""
    scan_path: str
    scan_timestamp: str
    scanner_version: str
    total_files_scanned: int
    total_lines_scanned: int
    findings: List[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'high')
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'medium')
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'low')
    
    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'info')
    
    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings filtered by MASVS category."""
        return [f for f in self.findings if f.masvs_category == category]
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def to_dict(self) -> dict:
        """Convert results to dictionary."""
        return {
            'scan_info': {
                'path': self.scan_path,
                'timestamp': self.scan_timestamp,
                'scanner_version': self.scanner_version,
                'duration_seconds': self.scan_duration_seconds
            },
            'statistics': {
                'total_files': self.total_files_scanned,
                'total_lines': self.total_lines_scanned,
                'total_findings': self.total_findings,
                'by_severity': {
                    'critical': self.critical_count,
                    'high': self.high_count,
                    'medium': self.medium_count,
                    'low': self.low_count,
                    'info': self.info_count
                }
            },
            'findings': [f.to_dict() for f in self.findings]
        }


class SecurityScanner:
    """
    Main scanner class that orchestrates vulnerability detection.
    
    This class coordinates the scanning process by:
    1. Discovering Dart files in the target path
    2. Loading and applying vulnerability patterns
    3. Mapping findings to MASVS controls
    4. Aggregating and returning results
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: ScannerConfig):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Scanner configuration object
        """
        self.config = config
        self.pattern_registry = PatternRegistry()
        self.masvs_mapper = MasvsMapper()
        
    def scan(self, path: Union[str, Path]) -> ScanResults:
        """
        Scan a Flutter project or Dart file for vulnerabilities.
        
        Args:
            path: Path to Flutter project directory or single Dart file
            
        Returns:
            ScanResults object containing all findings
        """
        start_time = datetime.now()
        path = Path(path)
        
        # Initialize results
        results = ScanResults(
            scan_path=str(path),
            scan_timestamp=start_time.isoformat(),
            scanner_version=self.VERSION,
            total_files_scanned=0,
            total_lines_scanned=0
        )
        
        # Discover Dart files
        dart_files = self._discover_dart_files(path)
        
        # Collect all Dart content for project-level analysis
        all_dart_content = []
        
        # Scan each file
        for dart_file in dart_files:
            file_findings, line_count, file_content = self._scan_file(dart_file)
            results.findings.extend(file_findings)
            results.total_files_scanned += 1
            results.total_lines_scanned += line_count
            all_dart_content.append(file_content)
        
        # Check pubspec.yaml for project-level security packages
        # Pass combined Dart content to check for sensitive functionality
        combined_dart_content = '\n'.join(all_dart_content)
        pubspec_findings = self._check_pubspec_security(path, combined_dart_content)
        results.findings.extend(pubspec_findings)
        
        # Apply severity filter
        if self.config.min_severity:
            results.findings = self._filter_by_severity(results.findings)
        
        # Apply MASVS category filter
        if self.config.masvs_categories:
            results.findings = self._filter_by_category(results.findings)
        
        # Calculate duration
        end_time = datetime.now()
        results.scan_duration_seconds = (end_time - start_time).total_seconds()
        
        return results
    
    def _discover_dart_files(self, path: Path) -> List[Path]:
        """
        Discover all Dart files in the given path.
        
        Args:
            path: Directory or file path
            
        Returns:
            List of Dart file paths
        """
        if path.is_file():
            if path.suffix == '.dart':
                return [path]
            return []
        
        dart_files = []
        
        # Directories to skip
        skip_dirs = {'.dart_tool', 'build', '.git', '.idea', 'ios', 'android', 'web', 'linux', 'macos', 'windows', 'test', 'tests', 'test_driver', 'integration_test'}
        
        for root, dirs, files in os.walk(path):
            # Remove directories to skip
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if file.endswith('.dart'):
                    dart_files.append(Path(root) / file)
        
        return dart_files
    
    def _scan_file(self, file_path: Path) -> tuple[List[Finding], int, str]:
        """
        Scan a single Dart file for vulnerabilities.
        
        Args:
            file_path: Path to Dart file
            
        Returns:
            Tuple of (list of findings, line count, file content)
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                line_count = len(lines)
        except (IOError, UnicodeDecodeError) as e:
            if self.config.verbose:
                print(f"Warning: Could not read {file_path}: {e}")
            return [], 0, ''
        
        # Apply each pattern
        for pattern in self.pattern_registry.get_all_patterns():
            matches = pattern.search(content, lines)
            
            for match in matches:
                finding = Finding(
                    vulnerability_id=pattern.vulnerability_id,
                    title=pattern.title,
                    description=pattern.description,
                    severity=pattern.severity,
                    file_path=str(file_path),
                    line_number=match['line_number'],
                    code_snippet=match['code_snippet'],
                    masvs_category=pattern.masvs_category,
                    masvs_control=pattern.masvs_control,
                    remediation=pattern.remediation,
                    cwe_id=pattern.cwe_id,
                    confidence=match.get('confidence', 'high')
                )
                findings.append(finding)
        
        return findings, line_count, content
    
    def _filter_by_severity(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by minimum severity level."""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        min_index = severity_order.index(self.config.min_severity)
        
        return [f for f in findings if severity_order.index(f.severity) >= min_index]
    
    def _filter_by_category(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by MASVS categories."""
        return [f for f in findings if f.masvs_category in self.config.masvs_categories]
    
    def _check_pubspec_security(self, path: Path, dart_files_content: str) -> List[Finding]:
        """
        Check pubspec.yaml for security-related packages.
        
        This checks for project-level security configurations like
        root/jailbreak detection packages, but ONLY if the app
        contains sensitive functionality.
        
        Args:
            path: Path to Flutter project directory
            dart_files_content: Combined content of all scanned Dart files
            
        Returns:
            List of findings for missing security packages
        """
        findings = []
        
        # Find pubspec.yaml
        if path.is_file():
            pubspec_path = path.parent / 'pubspec.yaml'
        else:
            pubspec_path = path / 'pubspec.yaml'
        
        # If no pubspec.yaml found, skip this check
        if not pubspec_path.exists():
            return findings
        
        try:
            with open(pubspec_path, 'r', encoding='utf-8') as f:
                pubspec_content = f.read().lower()
        except (IOError, UnicodeDecodeError):
            return findings
        
        # =====================================================
        # V022: Check for root/jailbreak detection packages
        # Only flag if app contains sensitive functionality
        # =====================================================
        
        # Step 1: Check if app has sensitive functionality
        sensitive_indicators = [
            # Crypto/Wallet related
            r'encrypt\s*\(',
            r'decrypt\s*\(',
            r'wallet',
            r'seed',
            r'private[_]?key',
            r'mnemonic',
            r'crypto',
            # Payment related
            r'payment',
            r'credit[_]?card',
            r'stripe',
            r'paypal',
            r'checkout',
            r'purchase',
            # Banking related
            r'bank',
            r'transfer',
            r'account[_]?balance',
            r'transaction',
            # Authentication related
            r'biometric',
            r'local[_]?auth',
            r'flutter_secure_storage',
            r'pin[_]?code',
            # Health related
            r'health[_]?data',
            r'medical',
            r'patient',
        ]
        
        import re
        dart_content_lower = dart_files_content.lower()
        
        # Check if ANY sensitive indicator is found
        has_sensitive_code = any(
            re.search(indicator, dart_content_lower) 
            for indicator in sensitive_indicators
        )
        
        # If no sensitive code, don't flag V022
        if not has_sensitive_code:
            return findings
        
        # Step 2: Check for root detection packages in pubspec.yaml
        root_detection_packages = [
            'flutter_jailbreak_detection',
            'root_checker',
            'safe_device',
            'freerasp',
            'jailbreak_detection',
            'trust_fall',
        ]
        
        has_root_detection = any(pkg in pubspec_content for pkg in root_detection_packages)
        
        # Step 3: If sensitive code exists but no root detection, flag it
        if not has_root_detection:
            findings.append(Finding(
                vulnerability_id='V022',
                title='Missing Root/Jailbreak Detection',
                description='App contains sensitive functionality (crypto, payments, secure storage, or biometrics) but does not include root/jailbreak detection. Rooted devices can bypass app security controls and access protected data.',
                severity='medium',
                file_path=str(pubspec_path),
                line_number=1,
                code_snippet='# Sensitive code detected but no root/jailbreak detection package found in dependencies',
                masvs_category='RESILIENCE',
                masvs_control='MASVS-RESILIENCE-1',
                remediation='Add a root/jailbreak detection package to pubspec.yaml. Recommended packages: flutter_jailbreak_detection, freerasp, or safe_device.',
                cwe_id='CWE-919',
                confidence='high'
            ))
        
        # =====================================================
        # V013: Check for certificate pinning packages
        # Only flag if app uses HTTP clients (Dio, http, HttpClient)
        # but has no certificate pinning package installed
        # =====================================================
        
        # Step 1: Check if app uses HTTP client libraries
        http_client_indicators = [
            r'dio',               # Dio package
            r'package:http/',     # http package
            r'HttpClient',        # dart:io HttpClient
        ]
        
        uses_http_clients = any(
            re.search(indicator, dart_files_content)
            for indicator in http_client_indicators
        )
        
        # Step 2: Check pubspec.yaml for cert pinning packages
        cert_pinning_packages = [
            'http_certificate_pinning',
            'ssl_pinning_plugin',
            'dio_http2_adapter',
            'certificate_pinning',
            'trust_fall',
            'freerasp',          # freeRASP also includes cert pinning
        ]
        
        has_cert_pinning = any(pkg in pubspec_content for pkg in cert_pinning_packages)
        
        # Step 3: If app uses HTTP clients but no pinning, flag it
        if uses_http_clients and not has_cert_pinning:
            findings.append(Finding(
                vulnerability_id='V013',
                title='Missing Certificate Pinning',
                description='App uses HTTP client libraries (Dio, http, or HttpClient) but does not include a certificate pinning package. Without pinning, attackers with CA-signed certificates can perform man-in-the-middle attacks.',
                severity='medium',
                file_path=str(pubspec_path),
                line_number=1,
                code_snippet='# HTTP client usage detected but no certificate pinning package found in dependencies',
                masvs_category='NETWORK',
                masvs_control='MASVS-NETWORK-2',
                remediation='Add a certificate pinning package to pubspec.yaml. Recommended: http_certificate_pinning, ssl_pinning_plugin, or dio_http2_adapter. Pin to leaf certificate or public key hash.',
                cwe_id='CWE-295',
                confidence='high'
            ))
        
        return findings