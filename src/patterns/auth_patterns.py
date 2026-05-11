"""
MASVS-AUTH Vulnerability Patterns

Patterns for detecting authentication and session management vulnerabilities.
Maps to OWASP MASVS v2.1.0 AUTH category.

Catalog Reference: V008-V010
"""

AUTH_PATTERNS = [
    {
        'vulnerability_id': 'V008',
        'title': 'Insecure Biometric Authentication',
        'description': 'Biometric authentication that only checks a boolean result without cryptographic binding. Attackers can bypass this with function hooking on rooted devices.',
        'severity': 'high',
        'masvs_category': 'AUTH',
        'masvs_control': 'MASVS-AUTH-2',
        'cwe_id': 'CWE-287',
        'remediation': 'Use biometrics with cryptographic binding. Store sensitive keys in the Keystore/Keychain and require biometric authentication to access them.',
        'patterns': [
            r'localAuth\.authenticate(?!.*biometricOnly)',
            r'LocalAuthentication.*authenticate.*\(\s*\)',
            r'authenticate\s*\([^)]*localizedReason[^)]*\)(?!.*useErrorDialogs)',
            r'canCheckBiometrics(?!.*isDeviceSupported)',
        ],
        'false_positive_patterns': [
            r'cryptographic',
            r'Keystore',
            r'Keychain',
            r'biometricOnly\s*:\s*true',
        ]
    },
    {
        'vulnerability_id': 'V009',
        'title': 'Missing Session Timeout',
        'description': 'App does not implement session timeout, allowing indefinite session validity. Compromised tokens remain valid indefinitely.',
        'severity': 'medium',
        'masvs_category': 'AUTH',
        'masvs_control': 'MASVS-AUTH-1',
        'cwe_id': 'CWE-613',
        'remediation': 'Implement session timeout with automatic logout. Use token expiration and refresh tokens. Consider idle timeout based on user inactivity.',
        'patterns': [
            r'(?:token|session).*(?:save|store|persist)(?!.*expir)',
            r'setString\s*\(\s*["\'](?:token|session|jwt)["\']',
            r'jwt_decode(?!.*exp)',
            r'JwtDecoder\.decode(?!.*isExpired)',
        ],
        'false_positive_patterns': [
            r'isExpired',
            r'expiresAt',
            r'tokenExpiry',
            r'sessionTimeout',
            r'refreshToken',
            # NOTE: kOption/kWindow/kEvent constants, code-generated model fields,
            # and function declarations/calls with session/token in names are now
            # handled by the shared Dart/Flutter whitelist in base_pattern.py.
            # V009-specific FP filters:
            # UI labels and display strings mentioning sessions
            r"""['"]\s*(?:Keep|Restore|Save|Active|Display)\s+.*[Ss]ession""",
            # Terminal/connection session management (not auth sessions)
            r'(?:terminal|persistent|restore|close|cleanup)\w*[Ss]ession',
            # Variables named *TokenKey or *token used for non-auth purposes
            r'(?:restore|wayland|tab)\w*[Tt]oken',
            # Sorted/filtered session lists (data processing, not session storage)
            r'(?:sorted|filtered|persistent)[Ss]essions',
            # ReceiveSession data models (file transfer sessions, not auth sessions)
            r'Receive[Ss]ession',
            # Display/show tokens (UI tokens, not auth tokens)
            r'[Ss]how[Tt]oken',
        ]
    },
    {
        'vulnerability_id': 'V010',
        'title': 'Weak Local PIN/Password Policy',
        'description': 'App allows weak PINs (e.g., 4 digits, no complexity requirements) or passwords without enforcing strength requirements.',
        'severity': 'medium',
        'masvs_category': 'AUTH',
        'masvs_control': 'MASVS-AUTH-2',
        'cwe_id': 'CWE-521',
        'remediation': 'Enforce strong PIN/password policy: minimum 6 digits for PIN, 8+ characters with complexity for passwords. Block common PINs (1234, 0000) and weak passwords.',
        'patterns': [
            r'pin\.length\s*[=<>!]+\s*[1-5]\b',
            r'password\.length\s*[<>=!]+\s*[1-7]\b',
            # Removed: if (pin != null) — standard null check, not weak validation
            # Only flag isNotEmpty when it's the SOLE validation before using the password
            # password.isNotEmpty as a null check before storage/transmission is normal
        ],
        'false_positive_patterns': [
            r'pin\.length\s*>=?\s*[6-9]',
            r'password\.length\s*>=?\s*(?:[8-9]|[1-9]\d)',
            r'RegExp.*(?:uppercase|lowercase|digit|special)',
            r'passwordStrength',
        ]
    },
]
