"""
MASVS-PLATFORM Vulnerability Patterns

Patterns for detecting platform interaction vulnerabilities in Flutter/Dart code.
Maps to OWASP MASVS v2.1.0 PLATFORM category.

Catalog Reference: V014-V017
"""

PLATFORM_PATTERNS = [
    {
        'vulnerability_id': 'V014',
        'title': 'Insecure Deep Link Handling',
        'description': 'Deep links that don\'t validate input before processing sensitive operations. Attackers can craft malicious deep links to trigger unintended actions.',
        'severity': 'medium',
        'masvs_category': 'PLATFORM',
        'masvs_control': 'MASVS-PLATFORM-1',
        'cwe_id': 'CWE-939',
        'remediation': 'Validate all deep link parameters. Implement allowlist for valid deep link paths. Require authentication for sensitive deep link actions.',
        'patterns': [
            r'onGenerateRoute\s*:\s*\([^)]*\)\s*{',
            r'uni_links.*getInitialLink',
            r'app_links.*getInitialAppLink',
            r'getInitialLink\s*\(\s*\)\.then',
            r'linkStream\.listen',
        ],
        'false_positive_patterns': [
            r'validate.*[Ll]ink',
            r'sanitize.*[Uu]ri',
            r'isValidDeepLink',
            r'verifyDeepLink',
        ]
    },
    {
        'vulnerability_id': 'V015',
        'title': 'WebView with JavaScript Enabled',
        'description': 'WebView components with JavaScript enabled loading untrusted content. JavaScript can be used for XSS attacks or to access sensitive WebView APIs.',
        'severity': 'medium',
        'masvs_category': 'PLATFORM',
        'masvs_control': 'MASVS-PLATFORM-2',
        'cwe_id': 'CWE-749',
        'remediation': 'Disable JavaScript unless strictly required. Only load trusted content. Implement Content Security Policy. Validate and sanitize all URLs before loading.',
        'patterns': [
            r'javascriptMode\s*:\s*JavascriptMode\.unrestricted',
            r'javaScriptMode\s*:\s*JavaScriptMode\.unrestricted',
            r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            r'WebView\s*\([^)]*javascriptMode[^)]*unrestricted',
        ],
        'false_positive_patterns': [
            r'javascriptMode\s*:\s*JavascriptMode\.disabled',
            r'trustedDomain',
        ]
    },
    {
        'vulnerability_id': 'V016',
        'title': 'Exposed JavaScript Bridge',
        'description': 'JavaScript bridges that expose sensitive native functionality to web content. Malicious web content can invoke native functions.',
        'severity': 'high',
        'masvs_category': 'PLATFORM',
        'masvs_control': 'MASVS-PLATFORM-2',
        'cwe_id': 'CWE-749',
        'remediation': 'Minimize JavaScript bridge exposure. Validate all messages from JavaScript. Only expose necessary functions. Implement origin checking.',
        'patterns': [
            r'addJavaScriptChannel\s*\(',
            r'JavaScriptChannel\s*\(',
            r'evaluateJavascript\s*\([^)]*\$',
            r'runJavaScript\s*\([^)]*\+',
            r'webViewController\.addJavaScriptChannel',
        ],
        'false_positive_patterns': [
            r'validateMessage',
            r'sanitizeInput',
            r'trustedOrigin',
        ]
    },
    {
        'vulnerability_id': 'V017',
        'title': 'Sensitive UI Not Protected from Screenshots',
        'description': 'Screens displaying sensitive data (passwords, financial info) are not protected from screenshots or screen recording. Data may leak through screenshots or recent apps view.',
        'severity': 'low',
        'masvs_category': 'PLATFORM',
        'masvs_control': 'MASVS-PLATFORM-3',
        'cwe_id': 'CWE-200',
        'remediation': 'Use flutter_windowmanager or platform channels to set FLAG_SECURE on Android. Use appropriate UIScreen settings on iOS. Implement screen capture detection.',
        'patterns': [
            r'TextField\s*\([^)]*obscureText\s*:\s*true',
            r'TextFormField\s*\([^)]*obscureText\s*:\s*true',
            r'CupertinoTextField\s*\([^)]*obscureText\s*:\s*true',
        ],
        'false_positive_patterns': [
            r'flutter_windowmanager',
            r'FlutterWindowManager',
            r'FLAG_SECURE',
            r'setSecureFlag',
        ]
    },
]