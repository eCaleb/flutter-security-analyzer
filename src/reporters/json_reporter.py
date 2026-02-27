"""
JSON Reporter Module

Outputs scan results in JSON format for CI/CD integration.
"""

import json
import sys
from typing import Optional

from core.scanner import ScanResults
from mappers.masvs_mapper import MasvsMapper


class JsonReporter:
    """
    Reporter that outputs findings in JSON format.
    
    This format is suitable for:
    - CI/CD pipeline integration
    - Automated processing
    - API responses
    - SARIF conversion
    """
    
    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize the JSON reporter.
        
        Args:
            output_path: If provided, output will be written to this file
        """
        self.output_path = output_path
        self.masvs_mapper = MasvsMapper()
    
    def generate(self, results: ScanResults):
        """
        Generate JSON report.
        
        Args:
            results: ScanResults object containing findings
        """
        report = self._build_report(results)
        json_output = json.dumps(report, indent=2)
        
        if self.output_path:
            self._write_to_file(json_output)
        else:
            print(json_output)
    
    def _build_report(self, results: ScanResults) -> dict:
        """Build the JSON report structure."""
        return {
            'scanner': {
                'name': 'Flutter Security Scanner',
                'version': results.scanner_version,
                'project': 'MSc Cybersecurity - University of Chester'
            },
            'scan': {
                'path': results.scan_path,
                'timestamp': results.scan_timestamp,
                'duration_seconds': results.scan_duration_seconds,
                'files_scanned': results.total_files_scanned,
                'lines_scanned': results.total_lines_scanned
            },
            'summary': {
                'total_findings': results.total_findings,
                'severity_counts': {
                    'critical': results.critical_count,
                    'high': results.high_count,
                    'medium': results.medium_count,
                    'low': results.low_count,
                    'info': results.info_count
                },
                'categories_affected': list(set(f.masvs_category for f in results.findings))
            },
            'compliance': self.masvs_mapper.get_compliance_summary(results.findings),
            'findings': [
                {
                    'id': f.vulnerability_id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'confidence': f.confidence,
                    'location': {
                        'file': f.file_path,
                        'line': f.line_number,
                        'code_snippet': f.code_snippet
                    },
                    'masvs': {
                        'category': f.masvs_category,
                        'control': f.masvs_control
                    },
                    'cwe_id': f.cwe_id,
                    'remediation': f.remediation
                }
                for f in results.findings
            ]
        }
    
    def _write_to_file(self, json_output: str):
        """Write JSON output to file."""
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write(json_output)
        except IOError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
