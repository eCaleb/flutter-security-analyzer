"""
MASVS-RESILIENCE Vulnerability Patterns

Patterns for detecting anti-tampering and reverse engineering weaknesses.
Maps to OWASP MASVS v2.1.0 RESILIENCE category.

Catalog Reference: V022-V024
"""

RESILIENCE_PATTERNS = [
    {
        'vulnerability_id': 'V022',
        'title': 'Missing Root/Jailbreak Detection',
        'description': 'App does not detect if running on a rooted/jailbroken device. Rooted devices can bypass app security controls and access protected data.',
        'severity': 'medium',
        'masvs_category': 'RESILIENCE',
        'masvs_control': 'MASVS-RESILIENCE-1',
        'cwe_id': 'CWE-919',
        'remediation': 'Implement root/jailbreak detection using flutter_jailbreak_detection, root_checker, or safe_device packages. Take appropriate action (warn user, limit functionality, or exit) when detected.',
        'patterns': [
            # V022 is now handled separately by scanning pubspec.yaml
            # These patterns are intentionally left empty
        ],
        'false_positive_patterns': []
    },
    {
        'vulnerability_id': 'V023',
        'title': 'Missing App Integrity Verification',
        'description': 'App does not verify its own integrity, allowing modified or repackaged versions to run. Attackers can inject malicious code.',
        'severity': 'medium',
        'masvs_category': 'RESILIENCE',
        'masvs_control': 'MASVS-RESILIENCE-2',
        'cwe_id': 'CWE-354',
        'remediation': 'Implement app integrity checking using Play Integrity API (Android) or App Attest (iOS). Verify app signature at runtime. Use code signing verification.',
        'patterns': [
            # Patterns indicating apps handling sensitive data without integrity checks
            r'(?:payment|banking|financial)(?:Service|Manager|Controller)',
            r'(?:license|subscription|premium)(?:Check|Verify|Manager)',
        ],
        'false_positive_patterns': [
            r'PlayIntegrity',
            r'AppAttest',
            r'integrityCheck',
            r'signatureVerif',
            r'checksumValid',
            r'freeRASP',
        ]
    },
    {
        'vulnerability_id': 'V024',
        'title': 'Missing Code Obfuscation',
        'description': 'Release build does not use code obfuscation, making reverse engineering significantly easier. Class and method names reveal application logic.',
        'severity': 'low',
        'masvs_category': 'RESILIENCE',
        'masvs_control': 'MASVS-RESILIENCE-3',
        'cwe_id': 'CWE-656',
        'remediation': 'Enable Dart obfuscation in release builds using --obfuscate flag with --split-debug-info. Example: flutter build apk --obfuscate --split-debug-info=./debug-info',
        'patterns': [
            # Patterns detecting build commands without obfuscation
            r'flutter\s+build\s+(?:apk|appbundle|ios|ipa)(?!.*--obfuscate)',
        ],
        'false_positive_patterns': [
            r'--obfuscate',
            r'--split-debug-info',
            r'proguard',
        ]
    },
]