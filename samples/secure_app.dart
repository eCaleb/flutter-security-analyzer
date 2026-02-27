// =============================================================================
// SECURE FLUTTER APP - DEMONSTRATES PROPER SECURITY PRACTICES
// =============================================================================
// This file shows the secure implementation for each vulnerability pattern.
// Use this as a reference for remediation guidance.
//
// Author: Caleb Elebhose
// Project: MSc Cybersecurity - University of Chester
// =============================================================================

import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:sqflite/sqflite.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

// =============================================================================
// V001 FIX: Use Environment Variables or Secure Storage for Secrets
// =============================================================================
class SecureApiConfig {
  // SECURE: Load from environment or secure storage
  static Future<String> getApiKey() async {
    const storage = FlutterSecureStorage();
    return await storage.read(key: 'api_key') ?? '';
  }
  
  // Or use compile-time environment variables
  static const apiKey = String.fromEnvironment('API_KEY');
}

// =============================================================================
// V002 FIX: Use Flutter Secure Storage
// =============================================================================
class SecureStorage {
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  
  Future<void> saveUserCredentials(String token) async {
    // SECURE: Using encrypted storage
    await _secureStorage.write(key: 'auth_token', value: token);
  }
  
  Future<String?> getToken() async {
    return await _secureStorage.read(key: 'auth_token');
  }
}

// =============================================================================
// V003 FIX: Conditional Logging with Debug Mode Check
// =============================================================================
class SecureLogging {
  void logUserActivity(String action) {
    // SECURE: Only log in debug mode, never log sensitive data
    if (kDebugMode) {
      debugPrint('User action: $action');
    }
    // Never log passwords, tokens, or PII
  }
}

// =============================================================================
// V004 FIX: Avoid Clipboard for Sensitive Data or Clear After Timeout
// =============================================================================
class SecureClipboard {
  void copyWithWarning(BuildContext context, String data, {bool isSensitive = false}) {
    if (isSensitive) {
      // SECURE: Show warning dialog before copying sensitive data
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: Text('Security Warning'),
          content: Text('Copying sensitive data to clipboard. It will be cleared in 30 seconds.'),
          actions: [
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: data));
                // Clear after 30 seconds
                Future.delayed(Duration(seconds: 30), () {
                  Clipboard.setData(ClipboardData(text: ''));
                });
                Navigator.pop(context);
              },
              child: Text('Copy'),
            ),
          ],
        ),
      );
    }
  }
}

// =============================================================================
// V005 FIX: Use Strong Hashing Algorithms
// =============================================================================
class SecureHashing {
  String hashPassword(String password, String salt) {
    // SECURE: Using SHA-256 with salt (for demo - use bcrypt/Argon2 in production)
    var bytes = utf8.encode(password + salt);
    var hash = sha256.convert(bytes);
    return hash.toString();
  }
  
  // Better: Use a proper password hashing library like bcrypt
  // String hashPasswordSecure(String password) {
  //   return BCrypt.hashpw(password, BCrypt.gensalt());
  // }
}

// =============================================================================
// V006 FIX: Derive Keys from User Credentials
// =============================================================================
class SecureEncryption {
  Future<List<int>> deriveKey(String password, List<int> salt) async {
    // SECURE: Derive encryption key from password using PBKDF2
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    final secretKey = await pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(password)),
      nonce: salt,
    );
    return await secretKey.extractBytes();
  }
}

// =============================================================================
// V007 FIX: Use Cryptographically Secure Random
// =============================================================================
class SecureRandom {
  String generateToken() {
    // SECURE: Using cryptographically secure random
    final random = Random.secure();
    final values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64Url.encode(values);
  }
}

// =============================================================================
// V008 FIX: Biometric with Cryptographic Binding
// =============================================================================
class SecureBiometrics {
  final LocalAuthentication localAuth = LocalAuthentication();
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();
  
  Future<bool> authenticateAndDecrypt() async {
    // SECURE: Biometric protects access to cryptographic key
    final authenticated = await localAuth.authenticate(
      localizedReason: 'Authenticate to access your account',
      options: AuthenticationOptions(
        biometricOnly: true,
        stickyAuth: true,
      ),
    );
    
    if (authenticated) {
      // Key is stored in platform keystore, protected by biometrics
      final key = await secureStorage.read(key: 'encryption_key');
      return key != null;
    }
    return false;
  }
}

// =============================================================================
// V009 FIX: Implement Session Timeout
// =============================================================================
class SecureSession {
  final FlutterSecureStorage _storage = const FlutterSecureStorage();
  
  Future<void> saveToken(String token, {Duration validity = const Duration(hours: 1)}) async {
    // SECURE: Store token with expiration
    final expiresAt = DateTime.now().add(validity).toIso8601String();
    await _storage.write(key: 'auth_token', value: token);
    await _storage.write(key: 'token_expires_at', value: expiresAt);
  }
  
  Future<String?> getValidToken() async {
    final expiresAtStr = await _storage.read(key: 'token_expires_at');
    if (expiresAtStr == null) return null;
    
    final expiresAt = DateTime.parse(expiresAtStr);
    if (DateTime.now().isAfter(expiresAt)) {
      // Token expired, clear it
      await _storage.delete(key: 'auth_token');
      await _storage.delete(key: 'token_expires_at');
      return null;
    }
    
    return await _storage.read(key: 'auth_token');
  }
}

// =============================================================================
// V010 FIX: Strong PIN/Password Policy
// =============================================================================
class StrongPinPolicy {
  bool validatePin(String pin) {
    // SECURE: Require 6+ digits, no sequential or repeated patterns
    if (pin.length < 6) return false;
    if (RegExp(r'^(.)\1+$').hasMatch(pin)) return false; // No repeated digits
    if (_isSequential(pin)) return false;
    
    // Block common PINs
    const weakPins = ['123456', '654321', '000000', '111111'];
    if (weakPins.contains(pin)) return false;
    
    return true;
  }
  
  bool validatePassword(String password) {
    // SECURE: Strong password requirements
    if (password.length < 8) return false;
    if (!RegExp(r'[A-Z]').hasMatch(password)) return false; // Uppercase
    if (!RegExp(r'[a-z]').hasMatch(password)) return false; // Lowercase
    if (!RegExp(r'[0-9]').hasMatch(password)) return false; // Digit
    if (!RegExp(r'[!@#$%^&*(),.?":{}|<>]').hasMatch(password)) return false; // Special
    
    return true;
  }
  
  bool _isSequential(String pin) {
    for (int i = 0; i < pin.length - 1; i++) {
      if ((pin.codeUnitAt(i + 1) - pin.codeUnitAt(i)).abs() != 1) {
        return false;
      }
    }
    return true;
  }
}

// =============================================================================
// V011 FIX: Always Use HTTPS
// =============================================================================
class SecureNetwork {
  final baseUrl = 'https://api.example.com'; // SECURE: HTTPS
  
  Future<void> login(String username, String password) async {
    // SECURE: Using HTTPS
    final url = 'https://api.mybank.com/login';
    await http.post(Uri.parse(url), body: {
      'username': username,
      'password': password,
    });
  }
}

// =============================================================================
// V012 FIX: Proper Certificate Validation (Only Bypass in Debug)
// =============================================================================
class SecureCertificate {
  HttpClient createClient() {
    HttpClient client = HttpClient();
    // SECURE: Only bypass in debug mode for testing
    if (kDebugMode) {
      client.badCertificateCallback = (cert, host, port) => true;
    }
    // In release, use default strict validation
    return client;
  }
}

// =============================================================================
// V013 FIX: Implement Certificate Pinning
// =============================================================================
class WithPinning {
  Future<http.Response> makeSecureRequest(String url) async {
    // SECURE: Using certificate pinning
    // Use http_certificate_pinning or similar package
    SecurityContext context = SecurityContext.defaultContext;
    context.setTrustedCertificatesBytes(certificateBytes);
    
    HttpClient client = HttpClient(context: context);
    // Make request with pinned certificate
    throw UnimplementedError('Implement with certificate pinning package');
  }
}

// =============================================================================
// V014 FIX: Validate Deep Links
// =============================================================================
class SecureDeepLinks {
  static const allowedPaths = ['/home', '/profile', '/settings'];
  
  void handleDeepLink(String? link) {
    if (link == null) return;
    
    final uri = Uri.parse(link);
    
    // SECURE: Validate deep link parameters
    if (!_isValidDeepLink(uri)) {
      return; // Reject invalid deep links
    }
    
    // Safe to process
    navigateToPage(uri.path);
  }
  
  bool _isValidDeepLink(Uri uri) {
    // Check scheme
    if (uri.scheme != 'myapp' && uri.scheme != 'https') return false;
    
    // Check path is in allowlist
    if (!allowedPaths.contains(uri.path)) return false;
    
    // Validate parameters
    for (var param in uri.queryParameters.values) {
      if (_containsMaliciousContent(param)) return false;
    }
    
    return true;
  }
  
  bool _containsMaliciousContent(String value) {
    // Check for script injection, SQL injection patterns, etc.
    final maliciousPatterns = [
      RegExp(r'<script', caseSensitive: false),
      RegExp(r'javascript:', caseSensitive: false),
      RegExp(r'[\'"].*(?:OR|AND).*[\'"]', caseSensitive: false),
    ];
    return maliciousPatterns.any((p) => p.hasMatch(value));
  }
}

// =============================================================================
// V015 FIX: Restrict WebView JavaScript and Validate URLs
// =============================================================================
class SecureWebView extends StatelessWidget {
  static const trustedDomains = ['trusted-site.com', 'api.myapp.com'];
  
  @override
  Widget build(BuildContext context) {
    // SECURE: JavaScript disabled for untrusted content
    return WebView(
      initialUrl: 'https://trusted-site.com',
      javascriptMode: JavascriptMode.disabled, // Disable JavaScript
      navigationDelegate: (request) {
        // Only allow trusted domains
        final uri = Uri.parse(request.url);
        if (trustedDomains.contains(uri.host)) {
          return NavigationDecision.navigate;
        }
        return NavigationDecision.prevent;
      },
    );
  }
}

// =============================================================================
// V016 FIX: Validate JavaScript Bridge Messages
// =============================================================================
class SecureJsBridge {
  late WebViewController controller;
  static const allowedActions = ['getData', 'setTheme', 'navigate'];
  
  void setupBridge() {
    controller.addJavaScriptChannel(
      JavaScriptChannel(
        name: 'SecureBridge',
        onMessageReceived: (message) {
          // SECURE: Validate and sanitize messages
          final data = jsonDecode(message.message);
          final action = data['action'] as String?;
          
          if (action != null && allowedActions.contains(action)) {
            _executeAllowedAction(action, data['params']);
          }
        },
      ),
    );
  }
  
  void _executeAllowedAction(String action, dynamic params) {
    switch (action) {
      case 'getData':
        // Handle safely
        break;
      // ... other allowed actions
    }
  }
}

// =============================================================================
// V017 FIX: Protect Sensitive Screens from Screenshots
// =============================================================================
class SecureSensitiveScreen extends StatefulWidget {
  @override
  _SecureSensitiveScreenState createState() => _SecureSensitiveScreenState();
}

class _SecureSensitiveScreenState extends State<SecureSensitiveScreen> {
  @override
  void initState() {
    super.initState();
    // SECURE: Enable screenshot protection
    FlutterWindowManager.addFlags(FlutterWindowManager.FLAG_SECURE);
  }
  
  @override
  void dispose() {
    // Remove flag when leaving screen
    FlutterWindowManager.clearFlags(FlutterWindowManager.FLAG_SECURE);
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          TextField(
            obscureText: true,
            decoration: InputDecoration(labelText: 'Password'),
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// V018 FIX: Remove Debug Code in Production
// =============================================================================
class SecureDebugConfig {
  // SECURE: Use kDebugMode/kReleaseMode
  void logInfo(String message) {
    if (kDebugMode) {
      debugPrint('Debug: $message');
    }
    // No logging in release mode
  }
}

// =============================================================================
// V019 FIX: Use Parameterized Queries
// =============================================================================
class SecureDatabase {
  late Database db;
  
  Future<List<Map>> getUserByName(String userName) async {
    // SECURE: Using parameterized query
    return await db.rawQuery(
      'SELECT * FROM users WHERE name = ?',
      [userName],
    );
  }
  
  Future<void> insertUser(String name, String email) async {
    // SECURE: Using insert method
    await db.insert('users', {
      'name': name,
      'email': email,
    });
  }
}

// =============================================================================
// V020 FIX: Keep Dependencies Updated
// =============================================================================
// pubspec.yaml - Use latest secure versions:
// dependencies:
//   http: ^1.1.0  # Latest version
//   dio: ^5.3.0   # Latest version
//
// Run regularly: flutter pub outdated
// Subscribe to security advisories

// =============================================================================
// V021 FIX: Set Modern Minimum SDK Version
// =============================================================================
// android/app/build.gradle:
// minSdkVersion 23  // Android 6.0+ for modern security features
//
// ios/Podfile:
// platform :ios, '12.0'  // iOS 12+ for modern security

// =============================================================================
// V022 FIX: Implement Root/Jailbreak Detection
// =============================================================================
class WithRootDetection {
  Future<void> accessSecureData() async {
    // SECURE: Check for rooted device
    final isJailbroken = await FlutterJailbreakDetection.jailbroken;
    
    if (isJailbroken) {
      // Handle rooted device - warn user or limit functionality
      throw SecurityException('App cannot run on rooted/jailbroken devices');
    }
    
    // Safe to access secure data
    final secureStorage = FlutterSecureStorage();
    await secureStorage.read(key: 'encryption_key');
  }
}

// =============================================================================
// V023 FIX: Implement App Integrity Verification
// =============================================================================
class SecurePaymentService {
  Future<void> processPayment(double amount) async {
    // SECURE: Verify app integrity before sensitive operations
    final isIntegrityValid = await _verifyAppIntegrity();
    
    if (!isIntegrityValid) {
      throw SecurityException('App integrity check failed');
    }
    
    // Safe to process payment
    await chargeCard(amount);
  }
  
  Future<bool> _verifyAppIntegrity() async {
    // Use Play Integrity API (Android) or App Attest (iOS)
    // Implementation depends on platform
    return true; // Placeholder
  }
}

// =============================================================================
// V024 FIX: Enable Code Obfuscation
// =============================================================================
// Build with obfuscation:
// flutter build apk --obfuscate --split-debug-info=./debug-info
// flutter build ios --obfuscate --split-debug-info=./debug-info

// =============================================================================
// V025 FIX: Request Only Necessary Permissions
// =============================================================================
class MinimalPermissions {
  Future<void> requestCameraIfNeeded() async {
    // SECURE: Only request permissions when needed
    final status = await Permission.camera.status;
    if (status.isDenied) {
      // Show explanation first
      await showPermissionExplanation();
      await Permission.camera.request();
    }
  }
  
  Future<void> showPermissionExplanation() async {
    // Explain why permission is needed before requesting
  }
}

// =============================================================================
// V026 FIX: Avoid Persistent Identifiers
// =============================================================================
class PrivacyFriendlyTracking {
  String getAnonymousId() {
    // SECURE: Use instance-specific identifier that resets on reinstall
    final prefs = SharedPreferences.getInstance();
    String? instanceId = prefs.getString('instance_id');
    
    if (instanceId == null) {
      instanceId = Uuid().v4(); // Generate new UUID
      prefs.setString('instance_id', instanceId);
    }
    
    return instanceId;
  }
  
  // For advertising, use platform advertising ID with consent
  Future<String?> getAdvertisingIdWithConsent() async {
    final hasConsent = await _getUserConsent();
    if (!hasConsent) return null;
    
    // Only then get advertising ID
    return await AdvertisingId.id(true);
  }
}

// =============================================================================
// Main
// =============================================================================
void main() {
  runApp(SecureApp());
}

class SecureApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Flutter App',
      home: Scaffold(
        appBar: AppBar(title: Text('Secure App')),
        body: Center(
          child: Text('This app demonstrates secure coding practices'),
        ),
      ),
    );
  }
}
