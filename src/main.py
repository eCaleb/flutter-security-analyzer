#!/usr/bin/env python3
"""
Flutter Security Scanner - Main Entry Point

A static analysis tool for detecting security vulnerabilities in Flutter/Dart
applications with OWASP MASVS compliance mapping.

Author: Caleb Elebhose
Project: MSc Cybersecurity Final Year Project
University of Chester
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional

from core.scanner import SecurityScanner
from core.config import ScannerConfig
from reporters.console_reporter import ConsoleReporter
from reporters.json_reporter import JsonReporter
from reporters.html_reporter import HtmlReporter


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog='flutter-security-scanner',
        description='Static security analysis tool for Flutter/Dart applications',
        epilog='Part of MSc Cybersecurity Project - University of Chester'
    )
    
    parser.add_argument(
        'path',
        type=str,
        help='Path to Flutter project or Dart file to scan'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file path for report (default: stdout)'
    )
    
    parser.add_argument(
        '-f', '--format',
        type=str,
        choices=['console', 'json', 'html'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '-s', '--severity',
        type=str,
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='low',
        help='Minimum severity level to report (default: low)'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        default=None,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--masvs-category',
        type=str,
        nargs='+',
        choices=['STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY'],
        default=None,
        help='Filter by MASVS categories'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser.parse_args()


def create_reporter(format_type: str, output_path: Optional[str]):
    """Factory function to create appropriate reporter."""
    reporters = {
        'console': ConsoleReporter,
        'json': JsonReporter,
        'html': HtmlReporter
    }
    
    reporter_class = reporters.get(format_type, ConsoleReporter)
    return reporter_class(output_path)


def main() -> int:
    """Main entry point for the scanner."""
    args = parse_arguments()
    
    # Validate input path
    scan_path = Path(args.path)
    if not scan_path.exists():
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        return 1
    
    # Load configuration
    config = ScannerConfig(
        min_severity=args.severity,
        masvs_categories=args.masvs_category,
        verbose=args.verbose,
        config_file=args.config
    )
    
    # Initialize scanner
    scanner = SecurityScanner(config)
    
    # Perform scan
    if args.verbose:
        print(f"Scanning: {scan_path}")
    
    results = scanner.scan(scan_path)
    
    # Generate report
    reporter = create_reporter(args.format, args.output)
    reporter.generate(results)
    
    # Return exit code based on findings
    critical_count = sum(1 for r in results.findings if r.severity == 'critical')
    high_count = sum(1 for r in results.findings if r.severity == 'high')
    
    if critical_count > 0:
        return 2  # Critical findings
    elif high_count > 0:
        return 1  # High severity findings
    return 0  # Success


if __name__ == '__main__':
    sys.exit(main())
