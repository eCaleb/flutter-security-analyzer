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
            # Route/endpoint/key name constants (e.g., 'forgot_password', 'refresh_token')
            # These are lowercase_snake_case strings, not actual secrets
            r"""static\s+const\s+(?:\w+\s+)*\w+\s*=\s*['"][a-z_]{3,30}['"]""",
            # UI label strings (e.g., 'Password', 'Enter password')
            r"""['"](Enter\s+|Confirm\s+|New\s+|Old\s+|Current\s+)?[Pp]assword['"]\s*[,;)\]]""",
            # UI display strings with spaces (e.g., 'Forgot Password?', 'Reset Password')
            # Real secrets don't contain spaces
            r"""(?:const|final)\s+(?:\w+\s+)*\w+\s*=\s*['"][^'"]*\s+[^'"]*(?:[Pp]assword|[Tt]oken)[^'"]*['"]""",
            # Short string values (less than 8 chars) that happen to contain keyword
            r"""(?:password|token|secret|key)\s*[:=]\s*['"][^'"]{0,7}['"]""",
            # Hint text and label patterns
            r'(?:hint|label|placeholder|text)\s*:\s*["\'].*(?:password|token)',
            # Map key lookups (e.g., data['password'])
            r"""\[['"](?:password|token|key|secret)['"]\]""",
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
            # Only flag when a sensitive keyword appears as a QUOTED STRING key name
            # e.g., prefs.setString('password', value) or prefs.setString("auth_token", value)
            # Does NOT match: prefs.setBool(key, value) where 'key' is a variable
            r'(?:prefs|preferences|sharedPrefs|sharedPreferences)\??\s*\.\s*set(?:String|Int|Bool|Double)\s*\(\s*["\'](?:password|token|secret|credential|auth|session|pin)',
            r'SharedPreferences.*set(?:String|Int|Bool)\s*\(\s*["\'](?:password|token|secret|credential|auth|session|pin)',
        ],
        'false_positive_patterns': [
            r'flutter_secure_storage',
            r'EncryptedSharedPreferences',
            r'secureStorage',
            # Non-sensitive SharedPreferences keys
            r'(?:theme|locale|language|onboarding|remember_me|saved_email|first_launch|dark_mode|font_size|notification)',
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
            r'kDebugMode\s*\?\s*print',
        ],
        'context_false_positive_patterns': [
            r'kReleaseMode',
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
