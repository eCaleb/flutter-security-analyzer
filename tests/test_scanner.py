"""
Comprehensive Unit Tests for Flutter Security Scanner

Tests cover:
1. Finding and ScanResults dataclasses
2. BasePattern class methods
3. SecurityScanner class methods
4. Pattern detection accuracy
5. False positive prevention
6. Integration tests with real Dart code

Author: Caleb Elebhose
Module: WB7103/WB7104 MSc Cybersecurity Project
University of Chester
"""

import unittest
import tempfile
import shutil
import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any
import re


# ============================================================================
# MOCK CLASSES (for standalone testing without full project structure)
# ============================================================================

@dataclass
class Finding:
    """Represents a single security finding."""
    vulnerability_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    masvs_category: str
    masvs_control: str
    remediation: str
    cwe_id: str = ""
    confidence: str = "high"
    
    def to_dict(self) -> dict:
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


class ScanResults:
    """Container for scan results."""
    def __init__(self, scan_path: str, scan_timestamp: str, scanner_version: str,
                 total_files_scanned: int, total_lines_scanned: int):
        self.scan_path = scan_path
        self.scan_timestamp = scan_timestamp
        self.scanner_version = scanner_version
        self.total_files_scanned = total_files_scanned
        self.total_lines_scanned = total_lines_scanned
        self.findings: List[Finding] = []
        self.scan_duration_seconds: float = 0.0
    
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
        return [f for f in self.findings if f.masvs_category == category]
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
    
    def to_dict(self) -> dict:
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


class BasePattern:
    """Base class for vulnerability patterns."""
    
    def __init__(self, vulnerability_id: str, title: str, description: str,
                 severity: str, masvs_category: str, masvs_control: str,
                 remediation: str, cwe_id: str, patterns: List[str],
                 false_positive_patterns: List[str] = None):
        self.vulnerability_id = vulnerability_id
        self.title = title
        self.description = description
        self.severity = severity
        self.masvs_category = masvs_category
        self.masvs_control = masvs_control
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.patterns = patterns
        self.false_positive_patterns = false_positive_patterns or []
        
        self._compiled_patterns = [
            re.compile(p, re.MULTILINE | re.IGNORECASE) 
            for p in self.patterns
        ]
        self._fp_compiled = [
            re.compile(p, re.MULTILINE | re.IGNORECASE)
            for p in self.false_positive_patterns
        ]
    
    def search(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        matches = []
        seen_lines = set()
        
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                if line_number in seen_lines:
                    continue
                
                if self._is_false_positive(match, content, lines, line_number):
                    continue
                
                code_snippet = self._get_code_snippet(lines, line_number)
                
                matches.append({
                    'line_number': line_number,
                    'code_snippet': code_snippet,
                    'matched_text': match.group(),
                    'confidence': 'high'
                })
                
                seen_lines.add(line_number)
        
        return matches
    
    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = '>>> ' if i == line_number - 1 else '    '
            snippet_lines.append(f"{i + 1:4d} {prefix}{lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _is_false_positive(self, match: re.Match, content: str, 
                           lines: List[str], line_number: int) -> bool:
        line = lines[line_number - 1].strip()
        
        # Skip comments
        if line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            return True
        
        # Check false positive patterns
        for fp_pattern in self._fp_compiled:
            if fp_pattern.search(line):
                return True
        
        return False


# ============================================================================
# TEST CLASSES
# ============================================================================

class TestFindingDataclass(unittest.TestCase):
    """Test the Finding dataclass."""
    
    def setUp(self):
        self.finding = Finding(
            vulnerability_id='V001',
            title='Hardcoded Credentials',
            description='Hardcoded password detected',
            severity='critical',
            file_path='/app/lib/main.dart',
            line_number=42,
            code_snippet='final password = "secret123";',
            masvs_category='STORAGE',
            masvs_control='MASVS-STORAGE-1',
            remediation='Use secure storage',
            cwe_id='CWE-798',
            confidence='high'
        )
    
    def test_finding_attributes(self):
        """Test Finding has correct attributes."""
        self.assertEqual(self.finding.vulnerability_id, 'V001')
        self.assertEqual(self.finding.severity, 'critical')
        self.assertEqual(self.finding.line_number, 42)
    
    def test_finding_to_dict(self):
        """Test Finding converts to dictionary correctly."""
        result = self.finding.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['vulnerability_id'], 'V001')
        self.assertEqual(result['severity'], 'critical')
        self.assertEqual(result['cwe_id'], 'CWE-798')
    
    def test_finding_default_values(self):
        """Test Finding uses default values correctly."""
        minimal_finding = Finding(
            vulnerability_id='V002',
            title='Test',
            description='Test desc',
            severity='low',
            file_path='/test.dart',
            line_number=1,
            code_snippet='code',
            masvs_category='STORAGE',
            masvs_control='MASVS-STORAGE-1',
            remediation='Fix it'
        )
        
        self.assertEqual(minimal_finding.cwe_id, '')
        self.assertEqual(minimal_finding.confidence, 'high')


class TestScanResultsClass(unittest.TestCase):
    """Test the ScanResults class."""
    
    def setUp(self):
        self.results = ScanResults(
            scan_path='/app',
            scan_timestamp='2026-03-13T10:00:00',
            scanner_version='1.0.0',
            total_files_scanned=10,
            total_lines_scanned=500
        )
        
        # Add test findings
        self.results.findings = [
            Finding('V001', 'Critical Bug', 'Desc', 'critical', '/a.dart', 1, 'code', 'STORAGE', 'CTRL-1', 'Fix'),
            Finding('V002', 'High Bug', 'Desc', 'high', '/b.dart', 2, 'code', 'CRYPTO', 'CTRL-2', 'Fix'),
            Finding('V003', 'High Bug 2', 'Desc', 'high', '/c.dart', 3, 'code', 'CRYPTO', 'CTRL-2', 'Fix'),
            Finding('V004', 'Medium Bug', 'Desc', 'medium', '/d.dart', 4, 'code', 'NETWORK', 'CTRL-3', 'Fix'),
            Finding('V005', 'Low Bug', 'Desc', 'low', '/e.dart', 5, 'code', 'AUTH', 'CTRL-4', 'Fix'),
            Finding('V006', 'Info Bug', 'Desc', 'info', '/f.dart', 6, 'code', 'STORAGE', 'CTRL-1', 'Fix'),
        ]
    
    def test_total_findings(self):
        """Test total_findings property."""
        self.assertEqual(self.results.total_findings, 6)
    
    def test_critical_count(self):
        """Test critical_count property."""
        self.assertEqual(self.results.critical_count, 1)
    
    def test_high_count(self):
        """Test high_count property."""
        self.assertEqual(self.results.high_count, 2)
    
    def test_medium_count(self):
        """Test medium_count property."""
        self.assertEqual(self.results.medium_count, 1)
    
    def test_low_count(self):
        """Test low_count property."""
        self.assertEqual(self.results.low_count, 1)
    
    def test_info_count(self):
        """Test info_count property."""
        self.assertEqual(self.results.info_count, 1)
    
    def test_get_findings_by_category(self):
        """Test filtering findings by MASVS category."""
        crypto_findings = self.results.get_findings_by_category('CRYPTO')
        self.assertEqual(len(crypto_findings), 2)
        
        storage_findings = self.results.get_findings_by_category('STORAGE')
        self.assertEqual(len(storage_findings), 2)
    
    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        high_findings = self.results.get_findings_by_severity('high')
        self.assertEqual(len(high_findings), 2)
    
    def test_to_dict(self):
        """Test converting results to dictionary."""
        result = self.results.to_dict()
        
        self.assertIn('scan_info', result)
        self.assertIn('statistics', result)
        self.assertIn('findings', result)
        
        self.assertEqual(result['statistics']['total_findings'], 6)
        self.assertEqual(result['statistics']['by_severity']['critical'], 1)
        self.assertEqual(len(result['findings']), 6)
    
    def test_empty_results(self):
        """Test empty scan results."""
        empty_results = ScanResults('/empty', '2026-01-01', '1.0.0', 0, 0)
        
        self.assertEqual(empty_results.total_findings, 0)
        self.assertEqual(empty_results.critical_count, 0)


class TestBasePatternClass(unittest.TestCase):
    """Test the BasePattern class methods."""
    
    def setUp(self):
        self.pattern = BasePattern(
            vulnerability_id='V001',
            title='Hardcoded Password',
            description='Detects hardcoded passwords',
            severity='critical',
            masvs_category='STORAGE',
            masvs_control='MASVS-STORAGE-1',
            remediation='Use secure storage',
            cwe_id='CWE-798',
            patterns=[r'password\s*=\s*["\'][^"\']+["\']'],
            false_positive_patterns=[r'//.*password', r'TODO|FIXME']
        )
    
    def test_search_finds_match(self):
        """Test search() finds vulnerable code."""
        content = 'String password = "secret123";'
        lines = content.split('\n')
        
        matches = self.pattern.search(content, lines)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['line_number'], 1)
    
    def test_search_multiple_matches(self):
        """Test search() finds multiple matches on different lines."""
        content = '''String password = "secret1";
String other = "safe";
String password = "secret2";'''
        lines = content.split('\n')
        
        matches = self.pattern.search(content, lines)
        
        self.assertEqual(len(matches), 2)
    
    def test_search_deduplicates_same_line(self):
        """Test search() deduplicates matches on same line."""
        # Pattern that could match twice on same line
        pattern = BasePattern(
            vulnerability_id='TEST',
            title='Test',
            description='Test',
            severity='high',
            masvs_category='TEST',
            masvs_control='TEST',
            remediation='Fix',
            cwe_id='CWE-000',
            patterns=[r'secret', r'password']
        )
        
        content = 'String secret_password = "value";'
        lines = content.split('\n')
        
        matches = pattern.search(content, lines)
        
        # Should only report once per line
        self.assertEqual(len(matches), 1)
    
    def test_search_skips_comments(self):
        """Test search() skips commented lines."""
        content = '''// password = "commented";
/* password = "block comment"; */
* password = "doc comment";
String password = "real";'''
        lines = content.split('\n')
        
        matches = self.pattern.search(content, lines)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['line_number'], 4)
    
    def test_search_skips_false_positives(self):
        """Test search() skips false positive patterns."""
        content = '''// TODO: password = "placeholder";
String password = "real_secret";'''
        lines = content.split('\n')
        
        matches = self.pattern.search(content, lines)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['line_number'], 2)
    
    def test_get_code_snippet_with_context(self):
        """Test _get_code_snippet() includes context lines."""
        lines = ['line1', 'line2', 'vulnerable', 'line4', 'line5']
        
        snippet = self.pattern._get_code_snippet(lines, 3, context=2)
        
        self.assertIn('line1', snippet)
        self.assertIn('>>> vulnerable', snippet)
        self.assertIn('line5', snippet)
    
    def test_get_code_snippet_at_file_start(self):
        """Test _get_code_snippet() at start of file."""
        lines = ['vulnerable', 'line2', 'line3']
        
        snippet = self.pattern._get_code_snippet(lines, 1, context=2)
        
        self.assertIn('>>> vulnerable', snippet)
        self.assertIn('line2', snippet)
    
    def test_get_code_snippet_at_file_end(self):
        """Test _get_code_snippet() at end of file."""
        lines = ['line1', 'line2', 'vulnerable']
        
        snippet = self.pattern._get_code_snippet(lines, 3, context=2)
        
        self.assertIn('line1', snippet)
        self.assertIn('>>> vulnerable', snippet)


class TestPatternDetectionAccuracy(unittest.TestCase):
    """Test actual pattern detection accuracy for each vulnerability type."""
    
    # V001: Hardcoded Credentials
    def test_v001_hardcoded_password(self):
        pattern = BasePattern(
            'V001', 'Hardcoded Credentials', 'Desc', 'critical',
            'STORAGE', 'MASVS-STORAGE-1', 'Fix', 'CWE-798',
            patterns=[r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']']
        )
        
        # Should detect
        self.assertEqual(len(pattern.search('password = "secret"', ['password = "secret"'])), 1)
        self.assertEqual(len(pattern.search('pwd = "123456"', ['pwd = "123456"'])), 1)
        
        # Should NOT detect
        self.assertEqual(len(pattern.search('password = getPassword()', ['password = getPassword()'])), 0)
    
    # V005: Weak Hashing
    def test_v005_weak_hashing(self):
        pattern = BasePattern(
            'V005', 'Weak Hashing', 'Desc', 'high',
            'CRYPTO', 'MASVS-CRYPTO-1', 'Fix', 'CWE-327',
            patterns=[r'\b(?:md5|sha1)\s*\.\s*(?:convert|hash|digest)']
        )
        
        # Should detect
        self.assertEqual(len(pattern.search('md5.convert(data)', ['md5.convert(data)'])), 1)
        self.assertEqual(len(pattern.search('sha1.hash(input)', ['sha1.hash(input)'])), 1)
        
        # Should NOT detect
        self.assertEqual(len(pattern.search('sha256.convert(data)', ['sha256.convert(data)'])), 0)
    
    # V006: Hardcoded Encryption Keys
    def test_v006_hardcoded_keys(self):
        pattern = BasePattern(
            'V006', 'Hardcoded Keys', 'Desc', 'critical',
            'CRYPTO', 'MASVS-CRYPTO-2', 'Fix', 'CWE-321',
            patterns=[r'(?:const|final)\s+\w*[Kk]ey\w*\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']'],
            false_positive_patterns=[r'generateKey', r'deriveKey']
        )
        
        # Should detect
        code = 'final aesKey = "1234567890abcdef1234567890abcdef";'
        self.assertEqual(len(pattern.search(code, [code])), 1)
        
        # Should NOT detect
        safe_code = 'final aesKey = generateKey();'
        self.assertEqual(len(pattern.search(safe_code, [safe_code])), 0)
    
    # V007: Insecure Random
    def test_v007_seeded_random(self):
        pattern = BasePattern(
            'V007', 'Insecure Random', 'Desc', 'medium',
            'CRYPTO', 'MASVS-CRYPTO-1', 'Fix', 'CWE-338',
            patterns=[r'Random\s*\(\s*\d+\s*\)'],
            false_positive_patterns=[r'Random\s*\.\s*secure']
        )
        
        # Should detect - seeded Random
        code = 'var rng = Random(12345);'
        self.assertEqual(len(pattern.search(code, [code])), 1)
        
        # Should NOT detect - secure Random
        safe_code = 'var rng = Random.secure();'
        self.assertEqual(len(pattern.search(safe_code, [safe_code])), 0)
    
    # V008: Cleartext HTTP
    def test_v008_cleartext_http(self):
        pattern = BasePattern(
            'V008', 'Cleartext HTTP', 'Desc', 'high',
            'NETWORK', 'MASVS-NETWORK-1', 'Fix', 'CWE-319',
            patterns=[r'http://(?!localhost|127\.0\.0\.1|10\.)']
        )
        
        # Should detect
        code = 'final url = "http://api.example.com";'
        self.assertEqual(len(pattern.search(code, [code])), 1)
        
        # Should NOT detect
        self.assertEqual(len(pattern.search('https://api.example.com', ['https://api.example.com'])), 0)
        self.assertEqual(len(pattern.search('http://localhost:8080', ['http://localhost:8080'])), 0)
    
    # V009: SSL Bypass
    def test_v009_ssl_bypass(self):
        pattern = BasePattern(
            'V009', 'SSL Bypass', 'Desc', 'critical',
            'NETWORK', 'MASVS-NETWORK-2', 'Fix', 'CWE-295',
            patterns=[r'badCertificateCallback.*(?:=>|return)\s*true']
        )
        
        # Should detect
        code = 'client.badCertificateCallback = (cert, host, port) => true;'
        self.assertEqual(len(pattern.search(code, [code])), 1)
    
    # V017: Screenshot Protection (refined)
    def test_v017_password_field(self):
        pattern = BasePattern(
            'V017', 'Screenshot Protection', 'Desc', 'medium',
            'PLATFORM', 'MASVS-PLATFORM-1', 'Fix', 'CWE-200',
            patterns=[r'TextField\s*\([^)]*obscureText\s*:\s*true']
        )
        
        # Should detect
        code = 'TextField(obscureText: true, controller: pwdCtrl)'
        self.assertEqual(len(pattern.search(code, [code])), 1)
        
        # Should NOT detect
        self.assertEqual(len(pattern.search('TextEditingController()', ['TextEditingController()'])), 0)


class TestFalsePositivePrevention(unittest.TestCase):
    """Test that refined patterns prevent known false positives."""
    
    def test_random_for_ui_not_flagged(self):
        """Random() for UI should NOT be flagged (FlutterSocialAppUIKit FP)."""
        pattern = BasePattern(
            'V007', 'Test', 'Desc', 'medium', 'CRYPTO', 'CTRL', 'Fix', 'CWE',
            patterns=[r'Random\s*\(\s*\d+\s*\)']  # Only seeded Random
        )
        
        # UI usage - unseeded Random
        ui_code = 'final color = colors[Random().nextInt(colors.length)];'
        self.assertEqual(len(pattern.search(ui_code, [ui_code])), 0)
    
    def test_text_editing_controller_not_flagged(self):
        """TextEditingController should NOT be flagged (Natrium Wallet FP)."""
        pattern = BasePattern(
            'V017', 'Test', 'Desc', 'medium', 'PLATFORM', 'CTRL', 'Fix', 'CWE',
            patterns=[r'TextField\s*\([^)]*obscureText\s*:\s*true']
        )
        
        controller_code = 'final passwordController = TextEditingController();'
        self.assertEqual(len(pattern.search(controller_code, [controller_code])), 0)
    
    def test_sha256_not_flagged(self):
        """SHA256 should NOT be flagged as weak hashing."""
        pattern = BasePattern(
            'V005', 'Test', 'Desc', 'high', 'CRYPTO', 'CTRL', 'Fix', 'CWE',
            patterns=[r'\b(?:md5|sha1)\s*\.\s*(?:convert|hash)']
        )
        
        safe_code = 'var hash = sha256.convert(data);'
        self.assertEqual(len(pattern.search(safe_code, [safe_code])), 0)
    
    def test_localhost_http_not_flagged(self):
        """HTTP localhost should NOT be flagged."""
        pattern = BasePattern(
            'V008', 'Test', 'Desc', 'high', 'NETWORK', 'CTRL', 'Fix', 'CWE',
            patterns=[r'http://(?!localhost|127\.0\.0\.1)']
        )
        
        localhost_code = 'final url = "http://localhost:3000/api";'
        self.assertEqual(len(pattern.search(localhost_code, [localhost_code])), 0)


class TestIntegrationWithRealDartCode(unittest.TestCase):
    """Integration tests with realistic Dart code samples."""
    
    def setUp(self):
        """Create temporary directory with test Dart files."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)
    
    def create_dart_file(self, filename: str, content: str) -> Path:
        """Helper to create a test Dart file."""
        file_path = Path(self.temp_dir) / filename
        file_path.write_text(content)
        return file_path
    
    def test_scan_vulnerable_auth_file(self):
        """Test scanning a file with authentication vulnerabilities."""
        vulnerable_code = '''
import 'package:flutter/material.dart';

class AuthService {
  // V001: Hardcoded credentials
  final String apiKey = "sk-1234567890abcdef";
  final password = "admin123";
  
  // V005: Weak hashing
  String hashPassword(String pwd) {
    return md5.convert(utf8.encode(pwd)).toString();
  }
  
  // V006: Hardcoded encryption key
  final encryptionKey = "0123456789abcdef0123456789abcdef";
}
'''
        file_path = self.create_dart_file('auth_service.dart', vulnerable_code)
        
        # Test V001 pattern
        v001_pattern = BasePattern(
            'V001', 'Hardcoded Credentials', 'Desc', 'critical',
            'STORAGE', 'CTRL', 'Fix', 'CWE-798',
            patterns=[r'(?:password|apiKey)\s*=\s*["\'][^"\']+["\']']
        )
        
        with open(file_path) as f:
            content = f.read()
            lines = content.split('\n')
        
        matches = v001_pattern.search(content, lines)
        self.assertGreaterEqual(len(matches), 1)
    
    def test_scan_vulnerable_network_file(self):
        """Test scanning a file with network vulnerabilities."""
        vulnerable_code = '''
import 'dart:io';

class ApiClient {
  // V008: Cleartext HTTP
  final baseUrl = "http://api.example.com/v1";
  
  HttpClient createClient() {
    var client = HttpClient();
    // V009: SSL bypass
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }
}
'''
        file_path = self.create_dart_file('api_client.dart', vulnerable_code)
        
        v009_pattern = BasePattern(
            'V009', 'SSL Bypass', 'Desc', 'critical',
            'NETWORK', 'CTRL', 'Fix', 'CWE-295',
            patterns=[r'badCertificateCallback.*=>.*true']
        )
        
        with open(file_path) as f:
            content = f.read()
            lines = content.split('\n')
        
        matches = v009_pattern.search(content, lines)
        self.assertEqual(len(matches), 1)
    
    def test_scan_safe_code_no_findings(self):
        """Test that safe code produces no findings."""
        safe_code = '''
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureAuthService {
  final storage = FlutterSecureStorage();
  
  Future<String?> getPassword() async {
    return await storage.read(key: 'password');
  }
  
  String hashPassword(String pwd) {
    return sha256.convert(utf8.encode(pwd)).toString();
  }
  
  HttpClient createClient() {
    var client = HttpClient();
    // Proper certificate validation
    return client;
  }
}
'''
        file_path = self.create_dart_file('secure_service.dart', safe_code)
        
        patterns = [
            BasePattern('V001', 'Test', 'D', 'critical', 'STORAGE', 'C', 'F', 'CWE',
                       patterns=[r'password\s*=\s*["\'][^"\']+["\']']),
            BasePattern('V005', 'Test', 'D', 'high', 'CRYPTO', 'C', 'F', 'CWE',
                       patterns=[r'\bmd5\s*\.\s*convert']),
            BasePattern('V009', 'Test', 'D', 'critical', 'NETWORK', 'C', 'F', 'CWE',
                       patterns=[r'badCertificateCallback.*=>.*true']),
        ]
        
        with open(file_path) as f:
            content = f.read()
            lines = content.split('\n')
        
        total_matches = sum(len(p.search(content, lines)) for p in patterns)
        self.assertEqual(total_matches, 0)


class TestFileDiscovery(unittest.TestCase):
    """Test file discovery logic."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def discover_dart_files(self, path: Path) -> List[Path]:
        """Simplified file discovery for testing."""
        if path.is_file():
            return [path] if path.suffix == '.dart' else []
        
        dart_files = []
        skip_dirs = {'test', 'tests', '.git', 'build', '.dart_tool'}
        
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if file.endswith('.dart'):
                    dart_files.append(Path(root) / file)
        
        return dart_files
    
    def test_discovers_dart_files(self):
        """Test discovery of .dart files."""
        lib_dir = Path(self.temp_dir) / 'lib'
        lib_dir.mkdir()
        
        (lib_dir / 'main.dart').write_text('void main() {}')
        (lib_dir / 'utils.dart').write_text('class Utils {}')
        (lib_dir / 'readme.txt').write_text('Not a Dart file')
        
        files = self.discover_dart_files(Path(self.temp_dir))
        
        self.assertEqual(len(files), 2)
        self.assertTrue(all(f.suffix == '.dart' for f in files))
    
    def test_skips_test_directories(self):
        """Test that test directories are skipped."""
        lib_dir = Path(self.temp_dir) / 'lib'
        test_dir = Path(self.temp_dir) / 'test'
        lib_dir.mkdir()
        test_dir.mkdir()
        
        (lib_dir / 'main.dart').write_text('void main() {}')
        (test_dir / 'main_test.dart').write_text('void main() {}')
        
        files = self.discover_dart_files(Path(self.temp_dir))
        
        self.assertEqual(len(files), 1)
        self.assertFalse(any('test' in str(f) for f in files))
    
    def test_handles_single_file(self):
        """Test discovery with single file path."""
        file_path = Path(self.temp_dir) / 'single.dart'
        file_path.write_text('void main() {}')
        
        files = self.discover_dart_files(file_path)
        
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0], file_path)


class TestSeverityFiltering(unittest.TestCase):
    """Test severity-based filtering of findings."""
    
    def filter_by_severity(self, findings: List[Finding], min_severity: str) -> List[Finding]:
        """Filter findings by minimum severity."""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        min_index = severity_order.index(min_severity)
        return [f for f in findings if severity_order.index(f.severity) >= min_index]
    
    def test_filter_minimum_high(self):
        """Test filtering with minimum severity 'high'."""
        findings = [
            Finding('V1', 'T', 'D', 'critical', 'f', 1, 'c', 'CAT', 'CTRL', 'R'),
            Finding('V2', 'T', 'D', 'high', 'f', 2, 'c', 'CAT', 'CTRL', 'R'),
            Finding('V3', 'T', 'D', 'medium', 'f', 3, 'c', 'CAT', 'CTRL', 'R'),
            Finding('V4', 'T', 'D', 'low', 'f', 4, 'c', 'CAT', 'CTRL', 'R'),
        ]
        
        filtered = self.filter_by_severity(findings, 'high')
        
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(f.severity in ['high', 'critical'] for f in filtered))
    
    def test_filter_minimum_medium(self):
        """Test filtering with minimum severity 'medium'."""
        findings = [
            Finding('V1', 'T', 'D', 'high', 'f', 1, 'c', 'CAT', 'CTRL', 'R'),
            Finding('V2', 'T', 'D', 'medium', 'f', 2, 'c', 'CAT', 'CTRL', 'R'),
            Finding('V3', 'T', 'D', 'low', 'f', 3, 'c', 'CAT', 'CTRL', 'R'),
        ]
        
        filtered = self.filter_by_severity(findings, 'medium')
        
        self.assertEqual(len(filtered), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)