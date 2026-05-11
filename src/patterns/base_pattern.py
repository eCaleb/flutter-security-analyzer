"""
Base Pattern Module

Defines the base class for all vulnerability detection patterns.
Includes a shared Dart/Flutter language whitelist that filters common
false positive patterns before individual vulnerability patterns run.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class PatternMatch:
    """Represents a pattern match in source code."""
    line_number: int
    code_snippet: str
    matched_text: str
    confidence: str = 'high'  # high, medium, low
    context: Optional[Dict[str, Any]] = None


# ============================================================================
# DART/FLUTTER LANGUAGE WHITELIST
#
# Common Dart and Flutter coding patterns that contain security-related
# keywords (password, token, key, session, secret, auth, pin) but are
# NOT security vulnerabilities. These are checked before any individual
# vulnerability pattern runs, eliminating false positives at the source.
#
# Three categories:
#   1. NAMING CONVENTIONS: Developer naming patterns where security keywords
#      appear in identifiers, not in actual data
#   2. LANGUAGE FEATURES: Dart/Flutter syntax that uses security keywords
#      as part of the language itself
#   3. CONFIGURATION PATTERNS: Config keys and settings that contain
#      security keywords as descriptive labels, not actual secrets
# ============================================================================

DART_LANGUAGE_WHITELIST = [

    # ===================================================================
    # CATEGORY 1: NAMING CONVENTIONS
    # Developers name things after what they do. A function that handles
    # password reset is called resetPassword(). A model for auth sessions
    # is called AuthSession. The security keyword is in the IDENTIFIER,
    # not in the DATA.
    # ===================================================================

    # 1.1 Flutter constant naming conventions
    # kOption*, kKey*, kWindow*, kEvent*, kDefault*, kMin*, kMax* prefixes
    # e.g., kOptionAllowDeepLinkPassword, kWindowEventActiveSession
    # e.g., kDefaultSessionTimeout, kMinPasswordLength
    r'(?:const\s+(?:\w+\s+)*)?_?k(?:Option|Key|Window|Event|Default|Min|Max|Is|Has|Enable|Disable|Allow)\w*\s*=',

    # 1.2 Function/method DECLARATIONS with security keywords in the name
    # Covers all Dart return types including void, Future, Stream, FutureOr
    # e.g., void wrongPasswordDialog(...), Future<bool> validateToken(...)
    # e.g., Stream<AuthState> watchSession(), bool isTokenExpired()
    r'(?:void|Future|FutureOr|Stream|Widget|Function|static|bool|String|int|double|dynamic|List|Map|Set|Iterator|Iterable|num)\s*<?[\w,\s]*>?\s+\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential|[Cc]ertificate)\w*\s*[<(]',

    # 1.3 Function/method CALLS where the name contains the keyword
    # e.g., showPasswordDialog(), validateToken(), checkSessionStatus()
    # e.g., parseAuthResponse(), encodeCredentials(), disposeSession()
    r'(?:wrong|show|on|handle|validate|check|verify|reset|forgot|change|update|set|get|create|build|clear|close|open|init|dispose|notify|parse|format|encode|decode|fetch|load|save|store|delete|remove|revoke|refresh|invalidate|emit|yield|return|throw|assert|expect|mock|stub|fake|when|verify|find|lookup|resolve|provide|inject|register|unregister|observe|watch|listen|subscribe|cancel|start|stop|toggle|enable|disable|grant|deny|request|approve|reject|confirm|accept|decline|prompt|ask|require|ensure|sanitize|hash|compare|match|test|is|has|can|should|will|must|need|try|attempt|process|convert|transform|map|filter|reduce|sort|group|merge|split|join|wrap|unwrap|extract|insert|append|prepend|push|pop|peek|enqueue|dequeue)\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential|[Cc]ertificate)\w*\s*[<(]',

    # 1.4 Class and type declarations/references
    # e.g., class PasswordValidator, class AuthSession, class TokenManager
    # e.g., mixin SessionMixin, extension AuthExtension on User
    r'(?:class|mixin|extension|enum|typedef)\s+\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential|[Cc]ertificate)\w*',

    # 1.5 Type annotations and generic type parameters
    # e.g., PasswordController controller, AuthState state, TokenResponse response
    # e.g., List<SessionModel> sessions, Map<String, AuthToken> tokens
    # e.g., Future<PasswordResetResult> result
    r'(?:[A-Z]\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential|[Cc]ertificate)\w*)\s+\w+\s*[;=,)\]]',
    r'(?:List|Map|Set|Future|Stream|Iterable|FutureOr|ValueNotifier|StateNotifier|ChangeNotifier|Provider|Riverpod)<\s*\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*\s*>',

    # 1.6 Enum values and enum member access
    # e.g., AuthState.authenticated, TokenType.bearer, SessionStatus.active
    # e.g., PasswordStrength.strong, KeyAlgorithm.rsa256
    r'\w+(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*\.\w+(?:\s*[;,)\]:]|\s*$)',

    # 1.7 Code-generated model fields (freezed, mappable, json_serializable, built_value)
    # e.g., _$saveToGallery(ReceiveSessionState v), Field<ReceiveSessionState>
    # e.g., _$AuthResponseFromJson, _$TokenModelCopyWith
    r'_\$\w*(?:[Ss]ession|[Tt]oken|[Kk]ey|[Pp]assword|[Aa]uth|[Cc]redential|[Ss]ecret)',
    r'Field<\w*(?:[Ss]ession|[Tt]oken|[Kk]ey|[Pp]assword|[Aa]uth|[Cc]redential|[Ss]ecret)',

    # 1.8 Named constructors and factory methods
    # e.g., Token.fromJson(), Session.create(), AuthState.initial()
    # e.g., Password.empty(), Credential.fromMap()
    r'\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*\.(?:from[A-Z]\w*|create|initial|empty|none|unknown|defaults?|copy[Ww]ith|to[A-Z]\w*|parse|try[A-Z]\w*)\s*\(',

    # 1.9 Getter and setter declarations
    # e.g., String get sessionId => _id, set authToken(String value)
    # e.g., bool get isAuthenticated, bool get hasValidToken
    r'(?:get|set)\s+\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*',
    r'(?:get|set)\s+(?:is|has|can|should|needs?)\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*',

    # 1.10 Variable declarations that are clearly type/state/status variables
    # e.g., bool isPasswordVisible, bool hasToken, AuthStatus authStatus
    # e.g., int tokenRetryCount, String passwordHint
    r'(?:bool|int|double|num)\s+(?:is|has|can|should|needs?|was|will|did)\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*',

    # ===================================================================
    # CATEGORY 2: DART/FLUTTER LANGUAGE FEATURES
    # Dart syntax and Flutter framework APIs that use security keywords
    # as part of the language/framework itself, not as application data.
    # ===================================================================

    # 2.1 Flutter widget constructor super.key parameter
    # Every StatelessWidget and StatefulWidget has an optional Key parameter
    # e.g., const MyWidget({required this.title, super.key})
    r'super\.key',

    # 2.2 Map/Iterable .keys property access
    # Dart Map has a .keys getter that returns all keys
    # e.g., onTapMap.keys.toList(), preferences.keys.where(...)
    r'\w+\.keys\b(?!\s*[:=])',

    # 2.3 Dart null safety and emptiness checks on security-named variables
    # These are type safety checks, not security validation
    # e.g., password.isNotEmpty, pin?.isEmpty, token == null
    r'(?:password|pin|token|secret|key|credential|session)(?:\?)?\.(?:isNotEmpty|isEmpty)\b',
    r'if\s*\(\s*(?:pin|password|token|secret|credential|session)\s*[!=]=\s*null\s*\)',

    # 2.4 Constructor field declarations (this.fieldName parameters)
    # e.g., required this.androidId, required this.sessionKey
    # e.g., this.passwordController, this.tokenExpiry
    r'(?:required\s+)?this\.(?:androidId|sessionId|tokenId|keyId|authId|passwordController|tokenExpiry|sessionTimeout|authState|keyStore|pinController|credentialManager)',

    # 2.5 Dart annotations and metadata
    # e.g., @JsonKey(name: 'auth_token'), @HiveField(3, defaultValue: '')
    # e.g., @override, @protected on security-related methods
    r"""@(?:JsonKey|HiveField|HiveType|FreezedUnionValue|Default|JsonSerializable|MappableField|BuiltValue|column|Column|Entity)\s*\([^)]*(?:password|token|secret|auth|session|key|pin|credential)""",

    # 2.6 Dart typedef and function type aliases
    # e.g., typedef TokenCallback = void Function(String token)
    # e.g., typedef PasswordValidator = bool Function(String)
    r'typedef\s+\w*(?:[Pp]assword|[Tt]oken|[Ss]ecret|[Aa]uth|[Ss]ession|[Kk]ey|[Pp]in|[Cc]redential)\w*\s*=',

    # 2.7 Dart cascade operator on security-named objects
    # e.g., passwordController..clear()..dispose()
    r'\w*(?:[Pp]assword|[Tt]oken|[Ss]ession|[Aa]uth|[Kk]ey|[Pp]in)\w*\s*\.\.',

    # 2.8 Import and export statements referencing security-named files/packages
    # e.g., import 'package:auth/auth.dart', import 'services/session_service.dart'
    r"""(?:import|export|part)\s+['"].*(?:password|token|secret|auth|session|key|pin|credential)""",

    # 2.9 String interpolation in UI/display strings (not logging)
    # When the line contains Text(), title:, label:, hint:, message:, description:
    # the interpolated security keyword is for display, not data leakage
    r'(?:Text|title|label|hint|message|description|tooltip|placeholder|helperText|errorText|counterText|prefixText|suffixText|semanticLabel)\s*[:(]\s*["\'].*(?:password|token|session|auth|key|pin)',

    # 2.10 Test framework assertions and matchers
    # e.g., expect(password, isNotNull), verify(mockAuth.login(any))
    # e.g., when(mockSession.getToken()).thenReturn('test')
    r'(?:expect|verify|when|setUp|tearDown|group|test|testWidgets)\s*\(.*(?:password|token|secret|auth|session|key|pin|credential)',

    # ===================================================================
    # CATEGORY 3: CONFIGURATION PATTERNS
    # Config keys, settings, and constants that contain security keywords
    # as descriptive labels, not as actual secrets or sensitive data.
    # ===================================================================

    # 3.1 Config option constants with kebab-case values (pure lowercase + hyphens)
    # e.g., const key = 'disable-change-permanent-password'
    # Excludes values with digits (which could be API keys like sk-proj-abc123)
    r"""(?:const|final)\s+(?:\w+\s+)*\w+\s*=\s*['"][a-z][a-z\-]{2,60}['"]""",

    # 3.2 Config option constants with snake_case values (lowercase + underscores)
    # e.g., static const refreshToken = 'refresh_token', const _key = 'auth_state'
    r"""static\s+const\s+(?:\w+\s+)*\w+\s*=\s*['"][a-z_]{3,30}['"]""",

    # 3.3 Variables ending in Key with config-style values
    # EXCLUDES actual secret-holding variable names
    r"""(?:const|final)\s+(?:\w+\s+)*(?!api[Kk]ey|secret[Kk]ey|private[Kk]ey|auth[Kk]ey|aes[Kk]ey|encryption[Kk]ey|hmac[Kk]ey|signing[Kk]ey|master[Kk]ey|server[Kk]ey|client[Kk]ey)\w*[Kk]ey\w*\s*=\s*['"][^'"]{3,60}['"]""",

    # 3.4 Private constants with app-specific prefixes (preferences/storage keys)
    # e.g., const _showToken = 'ls_show_token', const _authKey = 'app_auth_key'
    r"""const\s+_\w+\s*=\s*['"](?:ls_|app_|pref_|sp_|hive_|box_|cache_|db_|store_)[^'"]+['"]""",

    # 3.5 Named parameters for store/platform product IDs
    # e.g., androidId: 'com.app.donate_5', productId: 'premium_token'
    r"""androidId\s*:\s*['"]""",

    # 3.6 Environment variable lookups (reading config, not hardcoding)
    # e.g., Platform.environment['API_KEY'], dotenv.get('SECRET')
    # e.g., const.fromEnvironment('AUTH_TOKEN')
    r"""(?:Platform\.environment|dotenv\.(?:get|env)|String\.fromEnvironment|bool\.fromEnvironment|int\.fromEnvironment|const\.fromEnvironment)\s*[\[(]\s*['"]""",

    # 3.7 JSON/Map key access for parsing (reading field names, not secrets)
    # e.g., json['password'], data['auth_token'], map['session_id']
    # Only when preceded by a variable name (not print/log)
    r"""\w+\s*\[\s*['"](?:password|token|secret|auth|session|key|pin|credential)[^'"]*['"]\s*\]""",

    # 3.8 Route/path definitions containing security keywords
    # e.g., '/auth/login', '/api/v1/token/refresh', '/reset-password'
    r"""(?:route|path|url|uri|endpoint|api)\s*[:=]\s*['"][^'"]*(?:password|token|auth|session|login|logout|register|verify|reset|forgot)[^'"]*['"]""",

    # 3.9 SharedPreferences/Hive box key name constants
    # When the constant is defining the KEY NAME, not storing actual data
    # e.g., static const tokenKey = 'user_auth_token' (key name)
    # vs prefs.setString('user_auth_token', actualToken) (storing data - NOT whitelisted)
    r"""(?:static\s+)?const\s+\w*(?:[Kk]ey|[Nn]ame|[Ff]ield|[Cc]olumn|[Pp]roperty)\s*=\s*['"][^'"]*(?:password|token|auth|session|secret|pin|credential)[^'"]*['"]""",

    # 3.10 Error/exception message strings containing security keywords
    # e.g., throw Exception('Invalid session'), FormatException('Bad token format')
    # e.g., ArgumentError('Password cannot be null')
    r"""(?:throw\s+\w*(?:Exception|Error|Failure)|(?:Exception|Error|Failure|FormatException|ArgumentError|StateError|AssertionError)\s*\()\s*['"][^'"]*(?:password|token|auth|session|secret|key|pin|credential)""",
]

# Compile the whitelist once for performance
_COMPILED_WHITELIST = [
    re.compile(p, re.MULTILINE | re.IGNORECASE)
    for p in DART_LANGUAGE_WHITELIST
]


class BasePattern(ABC):
    """
    Abstract base class for vulnerability detection patterns.
    
    All vulnerability patterns must inherit from this class and implement
    the search method.
    """
    
    vulnerability_id: str
    title: str
    description: str
    severity: str
    masvs_category: str
    masvs_control: str
    remediation: str
    cwe_id: str
    patterns: List[str]
    
    def __init__(self):
        """Initialize the pattern and compile regex patterns."""
        self._compiled_patterns = [
            re.compile(p, re.MULTILINE | re.IGNORECASE) 
            for p in self.patterns
        ]
    
    def search(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Search for pattern matches in the given content.
        
        Args:
            content: Full file content as string
            lines: File content split into lines
            
        Returns:
            List of match dictionaries (deduplicated by line number)
        """
        matches = []
        seen_lines = set()  # Track which lines we've already matched
        
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                # Skip if we already have a finding on this line for this vulnerability
                if line_number in seen_lines:
                    continue
                
                if self._is_false_positive(match, content, lines, line_number):
                    continue
                
                code_snippet = self._get_code_snippet(lines, line_number)
                
                matches.append({
                    'line_number': line_number,
                    'code_snippet': code_snippet,
                    'matched_text': match.group(),
                    'confidence': self._calculate_confidence(match, content, lines)
                })
                
                seen_lines.add(line_number)  # Mark this line as matched
        
        return matches
    
    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Extract code snippet with surrounding context."""
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = '>>> ' if i == line_number - 1 else '    '
            snippet_lines.append(f"{i + 1:4d} {prefix}{lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _is_false_positive(self, match: re.Match, content: str, lines: List[str], line_number: int) -> bool:
        """Check if match is a false positive.
        
        Three-level false positive checking:
        1. SHARED WHITELIST: Dart/Flutter language patterns that are never vulnerabilities
        2. Comment detection: Lines starting with // or /* or *
        3. Pattern-specific filters (handled by RegexPattern subclass)
        """
        line = lines[line_number - 1]
        
        # Level 1: Check against the shared Dart/Flutter language whitelist
        # This catches common false positives from naming conventions,
        # language features, and configuration patterns
        for wp in _COMPILED_WHITELIST:
            if wp.search(line):
                return True
        
        # Level 2: Comment detection
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            return True
        
        return False
    
    def _calculate_confidence(self, match: re.Match, content: str, lines: List[str]) -> str:
        """Calculate confidence level for the match."""
        return 'high'


class RegexPattern(BasePattern):
    """Simple regex-based pattern."""
    
    def __init__(
        self,
        vulnerability_id: str,
        title: str,
        description: str,
        severity: str,
        masvs_category: str,
        masvs_control: str,
        remediation: str,
        cwe_id: str,
        patterns: List[str],
        false_positive_patterns: Optional[List[str]] = None,
        context_false_positive_patterns: Optional[List[str]] = None
    ):
        self.vulnerability_id = vulnerability_id
        self.title = title
        self.description = description
        self.severity = severity
        self.masvs_category = masvs_category
        self.masvs_control = masvs_control
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.patterns = patterns
        self.false_positive_patterns = false_positive_patterns or []
        self.context_false_positive_patterns = context_false_positive_patterns or []
        
        super().__init__()
        
        self._fp_compiled = [
            re.compile(p, re.MULTILINE | re.IGNORECASE)
            for p in self.false_positive_patterns
        ]
        self._context_fp_compiled = [
            re.compile(p, re.MULTILINE | re.IGNORECASE)
            for p in self.context_false_positive_patterns
        ]
    
    def _is_false_positive(self, match: re.Match, content: str, lines: List[str], line_number: int) -> bool:
        """Check for false positives using two strategies:
        
        1. LINE-LEVEL: Check the matched line against false_positive_patterns
           (e.g., comment markers, placeholder text)
        2. CONTEXT-LEVEL: Check surrounding lines (3 above, 1 below) against
           context_false_positive_patterns (e.g., kDebugMode guard clauses)
        
        Why context matters:
        In Flutter/Dart, guard clauses like 'if (kDebugMode)' appear on the
        line ABOVE the matched code. Checking only the matched line misses
        these guards, causing false positives for V018 and V003.
        """
        if super()._is_false_positive(match, content, lines, line_number):
            return True
        
        # Step 1: Check the MATCHED LINE against all FP patterns
        line = lines[line_number - 1]
        for fp_pattern in self._fp_compiled:
            if fp_pattern.search(line):
                return True
        
        # Step 2: Check SURROUNDING CONTEXT against context FP patterns only
        # Context window: 3 lines above + matched line + 1 line below
        if self._context_fp_compiled:
            context_start = max(0, line_number - 4)
            context_end = min(len(lines), line_number + 1)
            context_text = ' '.join(lines[context_start:context_end])
            
            for fp_pattern in self._context_fp_compiled:
                if fp_pattern.search(context_text):
                    return True
        
        return False