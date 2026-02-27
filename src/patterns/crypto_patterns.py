"""
MASVS-CRYPTO Vulnerability Patterns

Patterns for detecting cryptographic vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 CRYPTO category.

Catalog Reference: V005-V007
"""

CRYPTO_PATTERNS = [
    {
        'vulnerability_id': 'V005',
        'title': 'Weak Hashing Algorithms (MD5/SHA1)',
        'description': 'Using deprecated or weak hashing algorithms like MD5 or SHA1. These algorithms have known vulnerabilities and should not be used for security-sensitive operations.',
        'severity': 'high',
        'masvs_category': 'CRYPTO',
        'masvs_control': 'MASVS-CRYPTO-1',
        'cwe_id': 'CWE-327',
        'remediation': 'Use strong hashing algorithms: SHA-256, SHA-3, or bcrypt/Argon2 for password hashing. MD5/SHA1 are only acceptable for non-security checksums.',
        'patterns': [
            r'\b(?:md5|sha1)\s*\.\s*(?:convert|hash|digest)',
            r'import\s+["\']package:crypto/md5\.dart["\']',
            r'import\s+["\']package:crypto/sha1\.dart["\']',
            r'Md5\s*\(\s*\)',
            r'Sha1\s*\(\s*\)',
        ],
        'false_positive_patterns': [
            r'//.*(?:MD5|SHA1)',
            r'checksum',
            r'file.*hash',
            r'etag',
        ]
    },
    {
        'vulnerability_id': 'V006',
        'title': 'Hardcoded Encryption Keys',
        'description': 'Encryption keys hardcoded in source code. Compromises all encrypted data if source code is exposed through reverse engineering or repository access.',
        'severity': 'critical',
        'masvs_category': 'CRYPTO',
        'masvs_control': 'MASVS-CRYPTO-2',
        'cwe_id': 'CWE-321',
        'remediation': 'Generate keys dynamically, store in secure storage (flutter_secure_storage), or use a key management service. Derive keys from user credentials using PBKDF2/Argon2.',
        'patterns': [
            r'(?:encryption[_-]?key|aes[_-]?key|secret[_-]?key|crypto[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'(?:const|final)\s+\w*[Kk]ey\w*\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']',
            r'Key\s*\(\s*["\'][A-Za-z0-9+/=]{16,}["\']\s*\)',
            r'(?:const|final)\s+\w*[Ii][Vv]\w*\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        ],
        'false_positive_patterns': [
            r'//.*key',
            r'TODO|FIXME|example|test',
            r'generateKey',
            r'deriveKey',
        ]
    },
    {
        'vulnerability_id': 'V007',
        'title': 'Insecure Random Number Generation',
        'description': 'Using non-cryptographic random number generators for security-sensitive operations like token generation, nonces, or key generation.',
        'severity': 'medium',
        'masvs_category': 'CRYPTO',
        'masvs_control': 'MASVS-CRYPTO-1',
        'cwe_id': 'CWE-338',
        'remediation': 'Use Random.secure() for cryptographically secure random numbers in Dart. Never use math.Random() for security-sensitive operations.',
        'patterns': [
            r'Random\s*\(\s*\)(?!.*secure)',
            r'new\s+Random\s*\(',
            r'Random\s*\(\s*\d+\s*\)',
            r'math\.Random\s*\(',
        ],
        'false_positive_patterns': [
            r'Random\s*\.\s*secure',
            r'SecureRandom',
            r'Random\.secure\s*\(',
        ]
    },
]
