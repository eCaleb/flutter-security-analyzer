"""
MASVS-NETWORK Vulnerability Patterns

Patterns for detecting network security vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 NETWORK category.

Catalog Reference: V011-V013
"""

NETWORK_PATTERNS = [
    {
        'vulnerability_id': 'V011',
        'title': 'Insecure HTTP Connections',
        'description': 'Using unencrypted HTTP instead of HTTPS for network communication. Data transmitted in plaintext can be intercepted by attackers on the same network.',
        'severity': 'high',
        'masvs_category': 'NETWORK',
        'masvs_control': 'MASVS-NETWORK-1',
        'cwe_id': 'CWE-319',
        'remediation': 'Always use HTTPS for network communication. Configure Network Security Config on Android to block cleartext traffic. Use http package with https:// URLs only.',
        'patterns': [
            r'["\']http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)[^"\']+["\']',
            r'Uri\.parse\s*\(\s*["\']http://(?!localhost)',
            r'baseUrl\s*[:=]\s*["\']http://(?!localhost)',
            r'\.get\s*\(\s*["\']http://(?!localhost)',
            r'\.post\s*\(\s*["\']http://(?!localhost)',
        ],
        'false_positive_patterns': [
            r'http://localhost',
            r'http://127\.0\.0\.1',
            r'http://10\.',
            r'//.*http://',
            r'http://example\.com',
        ]
    },
    {
        'vulnerability_id': 'V012',
        'title': 'Disabled SSL/TLS Certificate Validation',
        'description': 'Disabling or bypassing SSL certificate validation allows man-in-the-middle attacks. Attackers can intercept and modify all network traffic.',
        'severity': 'critical',
        'masvs_category': 'NETWORK',
        'masvs_control': 'MASVS-NETWORK-1',
        'cwe_id': 'CWE-295',
        'remediation': 'Never disable certificate validation in production. Use certificate pinning for additional security. Only bypass for development with proper safeguards and kDebugMode checks.',
        'patterns': [
            r'badCertificateCallback\s*[:=]\s*\([^)]*\)\s*=>\s*true',
            r'onBadCertificate\s*[:=]\s*\([^)]*\)\s*=>\s*true',
            r'badCertificateCallback.*return\s+true',
            r'HttpOverrides\.global\s*=',
            r'allowLegacyUnsafeRenegotiation\s*[:=]\s*true',
        ],
        'false_positive_patterns': [
            r'kDebugMode',
            r'kReleaseMode\s*\?\s*false',
            r'if\s*\(\s*!kReleaseMode\s*\)',
        ]
    },
    # V013 has been moved to a project-level pubspec.yaml check
    # (see scanner.py _check_pubspec_security method)
    # Old approach: matching Dio() / http.Client() per line → massive false positives
    # New approach: check if app uses HTTP clients but has no cert pinning package
]
