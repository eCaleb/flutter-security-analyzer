"""
Scanner Configuration Module

Handles configuration loading and validation for the security scanner.
"""

import json
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    """
    Configuration settings for the security scanner.
    
    Attributes:
        min_severity: Minimum severity level to report
        masvs_categories: Filter results to specific MASVS categories
        verbose: Enable verbose output
        config_file: Path to optional configuration file
        exclude_patterns: File patterns to exclude from scanning
        include_tests: Whether to scan test files
        max_file_size_kb: Maximum file size to scan (in KB)
    """
    min_severity: str = 'low'
    masvs_categories: Optional[List[str]] = None
    verbose: bool = False
    config_file: Optional[str] = None
    exclude_patterns: List[str] = field(default_factory=lambda: ['*.g.dart', '*.freezed.dart'])
    include_tests: bool = False
    max_file_size_kb: int = 1024  # 1MB default
    
    # Severity levels in order
    SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical']
    
    # Valid MASVS categories
    MASVS_CATEGORIES = [
        'STORAGE',
        'CRYPTO', 
        'AUTH',
        'NETWORK',
        'PLATFORM',
        'CODE',
        'RESILIENCE',
        'PRIVACY'
    ]
    
    def __post_init__(self):
        """Validate and load configuration after initialization."""
        self._validate_severity()
        self._validate_categories()
        
        if self.config_file:
            self._load_config_file()
    
    def _validate_severity(self):
        """Validate severity level."""
        if self.min_severity not in self.SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity level: {self.min_severity}. "
                f"Must be one of: {', '.join(self.SEVERITY_LEVELS)}"
            )
    
    def _validate_categories(self):
        """Validate MASVS categories."""
        if self.masvs_categories:
            for category in self.masvs_categories:
                if category not in self.MASVS_CATEGORIES:
                    raise ValueError(
                        f"Invalid MASVS category: {category}. "
                        f"Must be one of: {', '.join(self.MASVS_CATEGORIES)}"
                    )
    
    def _load_config_file(self):
        """Load configuration from JSON file."""
        config_path = Path(self.config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")
        
        # Apply configuration values
        if 'min_severity' in config_data:
            self.min_severity = config_data['min_severity']
            self._validate_severity()
        
        if 'masvs_categories' in config_data:
            self.masvs_categories = config_data['masvs_categories']
            self._validate_categories()
        
        if 'exclude_patterns' in config_data:
            self.exclude_patterns = config_data['exclude_patterns']
        
        if 'include_tests' in config_data:
            self.include_tests = config_data['include_tests']
        
        if 'max_file_size_kb' in config_data:
            self.max_file_size_kb = config_data['max_file_size_kb']
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            'min_severity': self.min_severity,
            'masvs_categories': self.masvs_categories,
            'verbose': self.verbose,
            'exclude_patterns': self.exclude_patterns,
            'include_tests': self.include_tests,
            'max_file_size_kb': self.max_file_size_kb
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScannerConfig':
        """Create configuration from dictionary."""
        return cls(
            min_severity=data.get('min_severity', 'low'),
            masvs_categories=data.get('masvs_categories'),
            verbose=data.get('verbose', False),
            exclude_patterns=data.get('exclude_patterns', ['*.g.dart', '*.freezed.dart']),
            include_tests=data.get('include_tests', False),
            max_file_size_kb=data.get('max_file_size_kb', 1024)
        )
