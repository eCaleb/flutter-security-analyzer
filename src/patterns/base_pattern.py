"""
Base Pattern Module

Defines the base class for all vulnerability detection patterns.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class PatternMatch:
    """Represents a pattern match in source code."""
    line_number: int
    code_snippet: str
    matched_text: str
    confidence: str = 'high'  # high, medium, low
    context: Optional[Dict[str, Any]] = None


class BasePattern(ABC):
    """
    Abstract base class for vulnerability detection patterns.
    
    All vulnerability patterns must inherit from this class and implement
    the search method.
    """
    
    vulnerability_id: str
    title: str
    description: str
    severity: str
    masvs_category: str
    masvs_control: str
    remediation: str
    cwe_id: str
    patterns: List[str]
    
    def __init__(self):
        """Initialize the pattern and compile regex patterns."""
        self._compiled_patterns = [
            re.compile(p, re.MULTILINE | re.IGNORECASE) 
            for p in self.patterns
        ]
    
    def search(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Search for pattern matches in the given content.
        
        Args:
            content: Full file content as string
            lines: File content split into lines
            
        Returns:
            List of match dictionaries
        """
        matches = []
        
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                code_snippet = self._get_code_snippet(lines, line_number)
                
                if self._is_false_positive(match, content, lines, line_number):
                    continue
                
                matches.append({
                    'line_number': line_number,
                    'code_snippet': code_snippet,
                    'matched_text': match.group(),
                    'confidence': self._calculate_confidence(match, content, lines)
                })
        
        return matches
    
    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Extract code snippet with surrounding context."""
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = '>>> ' if i == line_number - 1 else '    '
            snippet_lines.append(f"{i + 1:4d} {prefix}{lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _is_false_positive(self, match: re.Match, content: str, lines: List[str], line_number: int) -> bool:
        """Check if match is a false positive."""
        line = lines[line_number - 1].strip()
        if line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            return True
        return False
    
    def _calculate_confidence(self, match: re.Match, content: str, lines: List[str]) -> str:
        """Calculate confidence level for the match."""
        return 'high'


class RegexPattern(BasePattern):
    """Simple regex-based pattern."""
    
    def __init__(
        self,
        vulnerability_id: str,
        title: str,
        description: str,
        severity: str,
        masvs_category: str,
        masvs_control: str,
        remediation: str,
        cwe_id: str,
        patterns: List[str],
        false_positive_patterns: Optional[List[str]] = None
    ):
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
        
        super().__init__()
        
        self._fp_compiled = [
            re.compile(p, re.MULTILINE | re.IGNORECASE)
            for p in self.false_positive_patterns
        ]
    
    def _is_false_positive(self, match: re.Match, content: str, lines: List[str], line_number: int) -> bool:
        """Check for false positives."""
        if super()._is_false_positive(match, content, lines, line_number):
            return True
        
        line = lines[line_number - 1]
        for fp_pattern in self._fp_compiled:
            if fp_pattern.search(line):
                return True
        
        return False
