"""
Patterns Module

Contains all vulnerability detection patterns organized by MASVS category.
Matches Flutter Vulnerability Catalog v2.0 (26 vulnerabilities).
"""

from .base_pattern import BasePattern, RegexPattern, PatternMatch
from .pattern_registry import PatternRegistry
from .storage_patterns import STORAGE_PATTERNS
from .crypto_patterns import CRYPTO_PATTERNS
from .auth_patterns import AUTH_PATTERNS
from .network_patterns import NETWORK_PATTERNS
from .platform_patterns import PLATFORM_PATTERNS
from .code_patterns import CODE_PATTERNS
from .resilience_patterns import RESILIENCE_PATTERNS
from .privacy_patterns import PRIVACY_PATTERNS

__all__ = [
    'BasePattern',
    'RegexPattern',
    'PatternMatch',
    'PatternRegistry',
    'STORAGE_PATTERNS',
    'CRYPTO_PATTERNS',
    'AUTH_PATTERNS',
    'NETWORK_PATTERNS',
    'PLATFORM_PATTERNS',
    'CODE_PATTERNS',
    'RESILIENCE_PATTERNS',
    'PRIVACY_PATTERNS'
]
