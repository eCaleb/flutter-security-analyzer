"""
Pattern Registry Module

Central registry for all vulnerability detection patterns.
Matches the Flutter Vulnerability Catalog v2.0 (26 vulnerabilities).
"""

from typing import List, Dict, Optional
from .base_pattern import BasePattern, RegexPattern

# Import all pattern categories
from .storage_patterns import STORAGE_PATTERNS
from .crypto_patterns import CRYPTO_PATTERNS
from .auth_patterns import AUTH_PATTERNS
from .network_patterns import NETWORK_PATTERNS
from .platform_patterns import PLATFORM_PATTERNS
from .code_patterns import CODE_PATTERNS
from .resilience_patterns import RESILIENCE_PATTERNS
from .privacy_patterns import PRIVACY_PATTERNS


class PatternRegistry:
    """
    Central registry for all vulnerability detection patterns.
    
    This class manages the loading and retrieval of vulnerability patterns
    organized by MASVS category.
    
    Catalog Mapping:
    - STORAGE: V001-V004 (4 patterns)
    - CRYPTO: V005-V007 (3 patterns)
    - AUTH: V008-V010 (3 patterns)
    - NETWORK: V011-V013 (3 patterns)
    - PLATFORM: V014-V017 (4 patterns)
    - CODE: V018-V021 (4 patterns)
    - RESILIENCE: V022-V024 (3 patterns)
    - PRIVACY: V025-V026 (2 patterns)
    
    Total: 26 vulnerability patterns
    """
    
    def __init__(self):
        """Initialize the registry and load all patterns."""
        self._patterns: Dict[str, List[BasePattern]] = {
            'STORAGE': [],
            'CRYPTO': [],
            'AUTH': [],
            'NETWORK': [],
            'PLATFORM': [],
            'CODE': [],
            'RESILIENCE': [],
            'PRIVACY': []
        }
        
        self._load_patterns()
    
    def _load_patterns(self):
        """Load all patterns from pattern modules."""
        # Load storage patterns (V001-V004)
        for pattern_def in STORAGE_PATTERNS:
            self._patterns['STORAGE'].append(self._create_pattern(pattern_def))
        
        # Load crypto patterns (V005-V007)
        for pattern_def in CRYPTO_PATTERNS:
            self._patterns['CRYPTO'].append(self._create_pattern(pattern_def))
        
        # Load auth patterns (V008-V010)
        for pattern_def in AUTH_PATTERNS:
            self._patterns['AUTH'].append(self._create_pattern(pattern_def))
        
        # Load network patterns (V011-V013)
        for pattern_def in NETWORK_PATTERNS:
            self._patterns['NETWORK'].append(self._create_pattern(pattern_def))
        
        # Load platform patterns (V014-V017)
        for pattern_def in PLATFORM_PATTERNS:
            self._patterns['PLATFORM'].append(self._create_pattern(pattern_def))
        
        # Load code patterns (V018-V021)
        for pattern_def in CODE_PATTERNS:
            self._patterns['CODE'].append(self._create_pattern(pattern_def))
        
        # Load resilience patterns (V022-V024)
        for pattern_def in RESILIENCE_PATTERNS:
            self._patterns['RESILIENCE'].append(self._create_pattern(pattern_def))
        
        # Load privacy patterns (V025-V026)
        for pattern_def in PRIVACY_PATTERNS:
            self._patterns['PRIVACY'].append(self._create_pattern(pattern_def))
    
    def _create_pattern(self, pattern_def: dict) -> RegexPattern:
        """Create a RegexPattern from a pattern definition dictionary."""
        return RegexPattern(
            vulnerability_id=pattern_def['vulnerability_id'],
            title=pattern_def['title'],
            description=pattern_def['description'],
            severity=pattern_def['severity'],
            masvs_category=pattern_def['masvs_category'],
            masvs_control=pattern_def['masvs_control'],
            remediation=pattern_def['remediation'],
            cwe_id=pattern_def.get('cwe_id', ''),
            patterns=pattern_def['patterns'],
            false_positive_patterns=pattern_def.get('false_positive_patterns', [])
        )
    
    def get_all_patterns(self) -> List[BasePattern]:
        """Get all registered patterns."""
        all_patterns = []
        for category_patterns in self._patterns.values():
            all_patterns.extend(category_patterns)
        return all_patterns
    
    def get_patterns_by_category(self, category: str) -> List[BasePattern]:
        """
        Get patterns for a specific MASVS category.
        
        Args:
            category: MASVS category name
            
        Returns:
            List of patterns for the category
        """
        return self._patterns.get(category, [])
    
    def get_pattern_by_id(self, vulnerability_id: str) -> Optional[BasePattern]:
        """
        Get a specific pattern by its vulnerability ID.
        
        Args:
            vulnerability_id: The vulnerability ID (e.g., 'V001')
            
        Returns:
            The pattern if found, None otherwise
        """
        for pattern in self.get_all_patterns():
            if pattern.vulnerability_id == vulnerability_id:
                return pattern
        return None
    
    def get_pattern_count(self) -> int:
        """Get total number of registered patterns."""
        return len(self.get_all_patterns())
    
    def get_category_counts(self) -> Dict[str, int]:
        """Get pattern counts by category."""
        return {
            category: len(patterns) 
            for category, patterns in self._patterns.items()
        }
    
    def get_catalog_summary(self) -> str:
        """Get a summary of the vulnerability catalog."""
        counts = self.get_category_counts()
        total = self.get_pattern_count()
        
        summary = "Flutter Vulnerability Catalog v2.0\n"
        summary += "=" * 40 + "\n"
        for category, count in counts.items():
            summary += f"MASVS-{category}: {count} patterns\n"
        summary += "=" * 40 + "\n"
        summary += f"Total: {total} vulnerability patterns\n"
        
        return summary
