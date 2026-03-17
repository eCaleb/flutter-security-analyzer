"""
MASVS-PRIVACY Vulnerability Patterns

Patterns for detecting privacy-related vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 PRIVACY category.

Catalog Reference: V025-V026
"""

PRIVACY_PATTERNS = [
    {
        'vulnerability_id': 'V025',
        'title': 'Excessive Permission Requests',
        'description': 'App requests more permissions than necessary for its functionality, violating the principle of least privilege and potentially exposing user data.',
        'severity': 'medium',
        'masvs_category': 'PRIVACY',
        'masvs_control': 'MASVS-PRIVACY-1',
        'cwe_id': 'CWE-250',
        'remediation': 'Review and minimize required permissions. Request permissions at runtime only when needed. Clearly explain to users why each permission is required.',
        'patterns': [
            # Only flag Android manifest entries requesting dangerous permissions
            # Individual Dart permission.request() calls are normal Flutter behaviour
            r'uses-permission.*(?:CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_CONTACTS|READ_SMS|READ_PHONE_STATE|READ_CALL_LOG|READ_EXTERNAL_STORAGE)',
            # Flag requesting many permissions in a single batch (4+ = suspicious)
            r'await\s*\[.*Permission\.\w+.*Permission\.\w+.*Permission\.\w+.*Permission\.\w+.*\]\.request\(\)',
        ],
        'false_positive_patterns': [
            r'permissionStatus',
            r'isGranted',
            r'checkPermission',
            r'<!--',  # Commented-out manifest entries
        ]
    },
    {
        'vulnerability_id': 'V026',
        'title': 'Collection of Persistent Device Identifiers',
        'description': 'App collects hardware identifiers (IMEI, MAC address, Android ID) that can track users across app reinstalls. This raises privacy concerns and may violate regulations.',
        'severity': 'medium',
        'masvs_category': 'PRIVACY',
        'masvs_control': 'MASVS-PRIVACY-2',
        'cwe_id': 'CWE-359',
        'remediation': 'Avoid collecting persistent device identifiers. Use instance-specific identifiers that reset on reinstall. For advertising, use the platform advertising ID with user consent.',
        'patterns': [
            r'androidId',
            r'Settings\.Secure\.ANDROID_ID',
            r'getIMEI\s*\(',
            r'getMacAddress\s*\(',
            r'identifierForVendor',
            r'advertisingIdentifier',
            r'DeviceInfoPlugin.*(?:androidId|identifierForVendor)',
            r'device_info_plus.*androidId',
        ],
        'false_positive_patterns': [
            r'advertisingId.*consent',
            r'privacyPolicy',
            r'userConsent',
        ]
    },
]
