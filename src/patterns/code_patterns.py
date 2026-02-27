"""
MASVS-CODE Vulnerability Patterns

Patterns for detecting code quality and security vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 CODE category.

Catalog Reference: V018-V021
"""

CODE_PATTERNS = [
    {
        'vulnerability_id': 'V018',
        'title': 'Debug Mode Enabled in Production',
        'description': 'Debug flags or assertions left enabled in production builds. Exposes sensitive debugging information and may enable hidden functionality.',
        'severity': 'medium',
        'masvs_category': 'CODE',
        'masvs_control': 'MASVS-CODE-4',
        'cwe_id': 'CWE-489',
        'remediation': 'Remove all debug code before release. Use kDebugMode/kReleaseMode flags to conditionally execute debug code. Verify build configuration excludes debug features.',
        'patterns': [
            r'(?:debugMode|isDebug)\s*[:=]\s*true',
            r'kDebugMode\s*\?\s*true',
            r'const\s+bool\s+isDebug\s*=\s*true',
            r'assert\s*\(\s*debugMode\s*==\s*true\s*\)',
            r'debugPrint\s*\(',
        ],
        'false_positive_patterns': [
            r'if\s*\(\s*kDebugMode\s*\)',
            r'kReleaseMode',
            r'!kDebugMode',
        ]
    },
    {
        'vulnerability_id': 'V019',
        'title': 'SQL Injection Vulnerability',
        'description': 'Building SQL queries through string concatenation with user input allows attackers to execute arbitrary SQL commands.',
        'severity': 'critical',
        'masvs_category': 'CODE',
        'masvs_control': 'MASVS-CODE-4',
        'cwe_id': 'CWE-89',
        'remediation': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use ORM libraries like Drift (formerly Moor).',
        'patterns': [
            r'rawQuery\s*\(\s*["\'][^"\']*\$',
            r'rawQuery\s*\(\s*["\'][^"\']*\+',
            r'(?:rawDelete|rawInsert|rawUpdate)\s*\(\s*["\'][^"\']*\$',
            r'(?:rawDelete|rawInsert|rawUpdate)\s*\(\s*["\'][^"\']*\+',
            r'execute\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)[^"\']*\$',
            r'db\.execute\s*\(\s*["\'][^"\']*\+',
        ],
        'false_positive_patterns': [
            r'rawQuery\s*\(\s*["\'][^"\']*\?\s*["\']',
            r'parameterized',
            r'preparedStatement',
        ]
    },
    {
        'vulnerability_id': 'V020',
        'title': 'Vulnerable Third-Party Dependencies',
        'description': 'Using third-party packages with known security vulnerabilities. Outdated dependencies may contain exploitable security flaws.',
        'severity': 'medium',
        'masvs_category': 'CODE',
        'masvs_control': 'MASVS-CODE-3',
        'cwe_id': 'CWE-1104',
        'remediation': 'Regularly update dependencies. Use `flutter pub outdated` to check for updates. Subscribe to security advisories for critical packages. Implement dependency scanning in CI/CD.',
        'patterns': [
            # Note: This vulnerability requires pubspec.yaml parsing and version checking
            # These patterns detect potential indicators
            r'http:\s*\^\s*0\.[0-9]',  # Very old http package
            r'dio:\s*\^\s*[0-3]\.',  # Old dio versions
            r'webview_flutter:\s*\^\s*[0-2]\.',  # Old webview
        ],
        'false_positive_patterns': []
    },
    {
        'vulnerability_id': 'V021',
        'title': 'Outdated Minimum SDK Version',
        'description': 'App supports outdated Android/iOS versions with known security vulnerabilities. Old platform versions lack modern security features.',
        'severity': 'medium',
        'masvs_category': 'CODE',
        'masvs_control': 'MASVS-CODE-1',
        'cwe_id': 'CWE-1104',
        'remediation': 'Set minSdkVersion to at least 23 (Android 6.0) for modern security features. For iOS, target iOS 12.0 or higher. Consider security implications of supporting older versions.',
        'patterns': [
            # Note: This requires build.gradle/Podfile parsing
            # These patterns match configuration files
            r'minSdkVersion\s+(?:1[0-9]|2[0-2])\b',  # Android SDK < 23
            r'minSdk\s*=\s*(?:1[0-9]|2[0-2])\b',
            r"platform\s*:ios\s*,\s*['\"](?:[0-9]|1[0-1])\.",  # iOS < 12
        ],
        'false_positive_patterns': [
            r'minSdkVersion\s+(?:2[3-9]|[3-9][0-9])',
            r'minSdk\s*=\s*(?:2[3-9]|[3-9][0-9])',
        ]
    },
]
