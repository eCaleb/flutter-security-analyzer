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
    {
        'vulnerability_id': 'V013',
        'title': 'Missing Certificate Pinning',
        'description': 'App does not implement certificate pinning, allowing attackers with CA-signed certificates to perform man-in-the-middle attacks.',
        'severity': 'medium',
        'masvs_category': 'NETWORK',
        'masvs_control': 'MASVS-NETWORK-2',
        'cwe_id': 'CWE-295',
        'remediation': 'Implement certificate pinning using packages like http_certificate_pinning or dio_http2_adapter. Pin to leaf certificate or public key hash.',
        'patterns': [
            r'Dio\s*\(\s*\)(?!.*interceptors)',
            r'http\.Client\s*\(\s*\)',
            r'HttpClient\s*\(\s*\)(?!.*SecurityContext)',
        ],
        'false_positive_patterns': [
            r'certificate.*pin',
            r'SecurityContext',
            r'http_certificate_pinning',
            r'setTrustedCertificates',
            r'ssl_pinning_plugin',
        ]
    },
]
