"""
Console Reporter Module

Outputs scan results to the console with colour formatting.
"""

import sys
from typing import Optional

from core.scanner import ScanResults


class ConsoleReporter:
    """
    Reporter that outputs findings to the console with formatting.
    """
    
    # ANSI colour codes
    COLOURS = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[96m',       # Cyan
        'info': '\033[90m',      # Grey
        'reset': '\033[0m',
        'bold': '\033[1m',
        'green': '\033[92m',
    }
    
    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize the console reporter.
        
        Args:
            output_path: If provided, output will also be written to this file
        """
        self.output_path = output_path
        self.output_lines = []
    
    def generate(self, results: ScanResults):
        """
        Generate and display console report.
        
        Args:
            results: ScanResults object containing findings
        """
        self._print_header(results)
        self._print_summary(results)
        self._print_findings(results)
        self._print_footer(results)
        
        # Write to file if path provided
        if self.output_path:
            self._write_to_file()
    
    def _print(self, text: str = "", colour: str = None):
        """Print text with optional colour."""
        if colour and colour in self.COLOURS:
            formatted = f"{self.COLOURS[colour]}{text}{self.COLOURS['reset']}"
        else:
            formatted = text
        
        print(formatted)
        # Store without ANSI codes for file output
        self.output_lines.append(text)
    
    def _print_header(self, results: ScanResults):
        """Print report header."""
        self._print()
        self._print("=" * 70, 'bold')
        self._print("  FLUTTER SECURITY SCANNER - SCAN RESULTS", 'bold')
        self._print("=" * 70, 'bold')
        self._print()
        self._print(f"  Scan Path:     {results.scan_path}")
        self._print(f"  Timestamp:     {results.scan_timestamp}")
        self._print(f"  Duration:      {results.scan_duration_seconds:.2f} seconds")
        self._print(f"  Files Scanned: {results.total_files_scanned}")
        self._print(f"  Lines Scanned: {results.total_lines_scanned}")
        self._print()
    
    def _print_summary(self, results: ScanResults):
        """Print findings summary."""
        self._print("-" * 70)
        self._print("  SUMMARY", 'bold')
        self._print("-" * 70)
        self._print()
        
        self._print(f"  Total Findings: {results.total_findings}")
        self._print()
        
        # Severity breakdown
        self._print(f"    Critical: {results.critical_count}", 'critical')
        self._print(f"    High:     {results.high_count}", 'high')
        self._print(f"    Medium:   {results.medium_count}", 'medium')
        self._print(f"    Low:      {results.low_count}", 'low')
        self._print(f"    Info:     {results.info_count}", 'info')
        self._print()
    
    def _print_findings(self, results: ScanResults):
        """Print detailed findings."""
        if not results.findings:
            self._print("  No vulnerabilities found!", 'green')
            self._print()
            return
        
        self._print("-" * 70)
        self._print("  DETAILED FINDINGS", 'bold')
        self._print("-" * 70)
        
        # Group by category
        categories = {}
        for finding in results.findings:
            if finding.masvs_category not in categories:
                categories[finding.masvs_category] = []
            categories[finding.masvs_category].append(finding)
        
        for category, findings in sorted(categories.items()):
            self._print()
            self._print(f"  [{category}] ({len(findings)} findings)", 'bold')
            self._print()
            
            for i, finding in enumerate(findings, 1):
                self._print_finding(finding, i)
    
    def _print_finding(self, finding, index: int):
        """Print a single finding."""
        severity_colour = finding.severity
        
        self._print(f"    {index}. [{finding.severity.upper()}] {finding.title}", severity_colour)
        self._print(f"       ID:          {finding.vulnerability_id}")
        self._print(f"       File:        {finding.file_path}")
        self._print(f"       Line:        {finding.line_number}")
        self._print(f"       MASVS:       {finding.masvs_control}")
        if finding.cwe_id:
            self._print(f"       CWE:         {finding.cwe_id}")
        self._print(f"       Confidence:  {finding.confidence}")
        self._print()
        self._print(f"       Description:")
        self._print(f"       {finding.description}")
        self._print()
        self._print(f"       Code:")
        for line in finding.code_snippet.split('\n'):
            self._print(f"       {line}")
        self._print()
        self._print(f"       Remediation:")
        self._print(f"       {finding.remediation}")
        self._print()
        self._print("       " + "-" * 50)
        self._print()
    
    def _print_footer(self, results: ScanResults):
        """Print report footer."""
        self._print("=" * 70)
        self._print("  Scan completed. Review findings and apply remediations.", 'bold')
        self._print("  For MASVS compliance details, see: https://mas.owasp.org/MASVS/")
        self._print("=" * 70)
        self._print()
    
    def _write_to_file(self):
        """Write output to file (without ANSI codes)."""
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.output_lines))
        except IOError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
