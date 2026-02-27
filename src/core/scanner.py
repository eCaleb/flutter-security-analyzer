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
        
        # Scan each file
        for dart_file in dart_files:
            file_findings, line_count = self._scan_file(dart_file)
            results.findings.extend(file_findings)
            results.total_files_scanned += 1
            results.total_lines_scanned += line_count
        
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
        skip_dirs = {'.dart_tool', 'build', '.git', '.idea', 'ios', 'android', 'web', 'linux', 'macos', 'windows'}
        
        for root, dirs, files in os.walk(path):
            # Remove directories to skip
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if file.endswith('.dart'):
                    dart_files.append(Path(root) / file)
        
        return dart_files
    
    def _scan_file(self, file_path: Path) -> tuple[List[Finding], int]:
        """
        Scan a single Dart file for vulnerabilities.
        
        Args:
            file_path: Path to Dart file
            
        Returns:
            Tuple of (list of findings, line count)
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
            return [], 0
        
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
        
        return findings, line_count
    
    def _filter_by_severity(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by minimum severity level."""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        min_index = severity_order.index(self.config.min_severity)
        
        return [f for f in findings if severity_order.index(f.severity) >= min_index]
    
    def _filter_by_category(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by MASVS categories."""
        return [f for f in findings if f.masvs_category in self.config.masvs_categories]
