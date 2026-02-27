"""
MASVS-STORAGE Vulnerability Patterns

Patterns for detecting insecure data storage vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 STORAGE category.

Catalog Reference: V001-V004
"""

STORAGE_PATTERNS = [
    {
        'vulnerability_id': 'V001',
        'title': 'Hardcoded API Keys/Secrets',
        'description': 'API keys, passwords, or secrets hardcoded directly in source code. Attackers can extract these through reverse engineering or by accessing the source repository.',
        'severity': 'high',
        'masvs_category': 'STORAGE',
        'masvs_control': 'MASVS-STORAGE-1',
        'cwe_id': 'CWE-798',
        'remediation': 'Store secrets in secure storage (flutter_secure_storage), environment variables, or a secrets management service. Never commit credentials to source control.',
        'patterns': [
            r'(?:api[_-]?key|apikey|secret|password|token|credential|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'(?:const|final)\s+\w*(?:key|secret|password|token|credential)\w*\s*=\s*["\'][^"\']+["\']',
            r'sk-[A-Za-z0-9]{20,}',
            r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        ],
        'false_positive_patterns': [
            r'//.*(?:api[_-]?key|password|token)',
            r'\*.*(?:api[_-]?key|password|token)',
            r'TODO|FIXME|example|placeholder|your[_-]?key|<.*>',
        ]
    },
    {
        'vulnerability_id': 'V002',
        'title': 'Sensitive Data in SharedPreferences',
        'description': 'Storing sensitive data (passwords, tokens, PII) in SharedPreferences without encryption. SharedPreferences data is stored in plaintext XML files accessible on rooted devices.',
        'severity': 'high',
        'masvs_category': 'STORAGE',
        'masvs_control': 'MASVS-STORAGE-1',
        'cwe_id': 'CWE-312',
        'remediation': 'Use flutter_secure_storage for sensitive data, which encrypts data using platform-specific secure storage (Keychain on iOS, EncryptedSharedPreferences on Android).',
        'patterns': [
            r'SharedPreferences.*set(?:String|Int|Bool).*\b(?:password|token|secret|key|credential|auth|session|pin)',
            r'(?:prefs|preferences|sharedPrefs)\s*\.\s*set(?:String|Int|Bool|Double)\s*\(\s*["\'](?:password|token|secret|key|credential|auth|session)',
            r'SharedPreferences\.getInstance',
        ],
        'false_positive_patterns': [
            r'flutter_secure_storage',
            r'EncryptedSharedPreferences',
            r'secureStorage',
        ]
    },
    {
        'vulnerability_id': 'V003',
        'title': 'Logging Sensitive Data',
        'description': 'Printing sensitive information (passwords, tokens, PII) to logs using print(), debugPrint(), or logging frameworks. Logs may be accessible through ADB or crash reports.',
        'severity': 'medium',
        'masvs_category': 'STORAGE',
        'masvs_control': 'MASVS-STORAGE-2',
        'cwe_id': 'CWE-532',
        'remediation': 'Remove sensitive data from logs. Use conditional logging that is disabled in release builds. Implement log sanitization.',
        'patterns': [
            r'(?:print|log|debugPrint|logger)\s*\(.*\b(?:password|token|secret|key|credential|session|auth)',
            r'print\s*\(\s*["\'].*(?:password|token|secret)',
            r'log\s*\(\s*["\'].*(?:Auth|Token|Password)',
        ],
        'false_positive_patterns': [
            r'kReleaseMode',
            r'kDebugMode\s*\?\s*print',
            r'if\s*\(\s*kDebugMode\s*\)',
        ]
    },
    {
        'vulnerability_id': 'V004',
        'title': 'Sensitive Data in Clipboard',
        'description': 'Copying sensitive data to the system clipboard. Other apps can access clipboard content, and it may persist after the app is closed.',
        'severity': 'medium',
        'masvs_category': 'STORAGE',
        'masvs_control': 'MASVS-STORAGE-2',
        'cwe_id': 'CWE-200',
        'remediation': 'Avoid copying sensitive data to clipboard. If necessary, clear clipboard after a timeout. Warn users before copying sensitive data.',
        'patterns': [
            r'Clipboard\.setData.*\b(?:password|token|secret|key|credential)',
            r'ClipboardData\s*\(.*(?:password|token|secret)',
        ],
        'false_positive_patterns': []
    },
]
