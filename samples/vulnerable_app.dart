// =============================================================================
// VULNERABLE FLUTTER APP - FOR TESTING PURPOSES ONLY
// =============================================================================
// This file contains intentional security vulnerabilities to test the
// Flutter Security Scanner. DO NOT use this code in production!
//
// Author: Caleb Elebhose
// Project: MSc Cybersecurity - University of Chester
// =============================================================================

import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:sqflite/sqflite.dart';
import 'package:local_auth/local_auth.dart';
import 'package:webview_flutter/webview_flutter.dart';

// =============================================================================
// V001: Hardcoded API Keys/Secrets (MASVS-STORAGE-1)
// =============================================================================
class ApiConfig {
  // VULNERABLE: Hardcoded API keys
  static const apiKey = 'FAKE_API_KEY_FOR_TESTING_ONLY_1234';
  static const String secretKey = 'my_super_secret_key_12345';
  static final password = 'admin123password';
  static const token =
      'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
}

// =============================================================================
// V002: Sensitive Data in SharedPreferences (MASVS-STORAGE-1)
// =============================================================================
class InsecureStorage {
  Future<void> saveUserCredentials(String password, String token) async {
    // VULNERABLE: Storing sensitive data in SharedPreferences
    SharedPreferences prefs = await SharedPreferences.getInstance();
    await prefs.setString('password', password);
    await prefs.setString('auth_token', token);
    await prefs.setString('session_key', 'secret_session_12345');
  }
}

// =============================================================================
// V003: Logging Sensitive Data (MASVS-STORAGE-2)
// =============================================================================
class InsecureLogging {
  void logUserActivity(String password, String token) {
    // VULNERABLE: Logging sensitive information
    print('User password: $password');
    print('Auth token: $token');
    debugPrint('Session secret: ${ApiConfig.secretKey}');
    log('User credentials - Password: $password, Token: $token');
  }
}

// =============================================================================
// V004: Sensitive Data in Clipboard (MASVS-STORAGE-2)
// =============================================================================
class InsecureClipboard {
  void copyPasswordToClipboard(String password) {
    // VULNERABLE: Copying sensitive data to clipboard
    Clipboard.setData(ClipboardData(text: password));
  }

  void copyTokenToClipboard(String token) {
    // VULNERABLE: Copying token to clipboard
    Clipboard.setData(ClipboardData(text: token));
  }
}

// =============================================================================
// V005: Weak Hashing Algorithms (MASVS-CRYPTO-1)
// =============================================================================
class InsecureHashing {
  String hashPassword(String password) {
    // VULNERABLE: Using MD5 for password hashing
    var bytes = utf8.encode(password);
    var hash = md5.convert(bytes);
    return hash.toString();
  }

  String hashToken(String token) {
    // VULNERABLE: Using SHA1 for security-sensitive hashing
    var bytes = utf8.encode(token);
    var hash = sha1.convert(bytes);
    return hash.toString();
  }
}

// =============================================================================
// V006: Hardcoded Encryption Keys (MASVS-CRYPTO-2)
// =============================================================================
class InsecureEncryption {
  // VULNERABLE: Hardcoded encryption keys
  static const String encryptionKey = 'MySecretKey12345MySecretKey12345';
  static const String aesKey = 'AES256SecretKeyForEncryption1234';
  static final iv = 'InitVector123456';

  void encrypt(String data) {
    final key = Key.fromUtf8('HardcodedKey1234HardcodedKey1234');
    // Encryption logic...
  }
}

// =============================================================================
// V007: Insecure Random Number Generation (MASVS-CRYPTO-1)
// =============================================================================
class InsecureRandom {
  String generateToken() {
    // VULNERABLE: Using non-cryptographic random
    var random = Random();
    var token = '';
    for (var i = 0; i < 32; i++) {
      token += random.nextInt(16).toRadixString(16);
    }
    return token;
  }

  String generateSessionId() {
    // VULNERABLE: Seeded random is predictable
    final random = Random(12345);
    return random.nextInt(999999).toString();
  }
}

// =============================================================================
// V008: Insecure Biometric Authentication (MASVS-AUTH-2)
// =============================================================================
class InsecureBiometrics {
  final LocalAuthentication localAuth = LocalAuthentication();

  Future<bool> authenticate() async {
    // VULNERABLE: Biometric without cryptographic binding
    final authenticated = await localAuth.authenticate(
      localizedReason: 'Authenticate to access your account',
    );
    return authenticated; // Just checking boolean result
  }
}

// =============================================================================
// V009: Missing Session Timeout (MASVS-AUTH-1)
// =============================================================================
class InsecureSession {
  Future<void> saveToken(String token) async {
    // VULNERABLE: No session timeout implemented
    SharedPreferences prefs = await SharedPreferences.getInstance();
    await prefs.setString('jwt', token);
    // Token stored indefinitely without expiration check
  }
}

// =============================================================================
// V010: Weak Local PIN/Password Policy (MASVS-AUTH-2)
// =============================================================================
class WeakPinPolicy {
  bool validatePin(String pin) {
    // VULNERABLE: Only checking length of 4
    if (pin.length == 4) {
      return true;
    }
    return false;
  }

  bool validatePassword(String password) {
    // VULNERABLE: Password only needs to be non-empty
    if (password.isNotEmpty) {
      return true;
    }
    return false;
  }
}

// =============================================================================
// V011: Insecure HTTP Connections (MASVS-NETWORK-1)
// =============================================================================
class InsecureNetwork {
  final baseUrl = 'http://api.example.com';

  Future<void> login(String username, String password) async {
    // VULNERABLE: Using HTTP instead of HTTPS
    final url = 'http://api.mybank.com/login';
    await http.post(Uri.parse(url), body: {
      'username': username,
      'password': password,
    });
  }

  Future<void> fetchData() async {
    // VULNERABLE: HTTP connection
    final response = await http.get(Uri.parse('http://data.example.com/users'));
  }
}

// =============================================================================
// V012: Disabled SSL/TLS Certificate Validation (MASVS-NETWORK-1)
// =============================================================================
class InsecureCertificate {
  HttpClient createUnsafeClient() {
    // VULNERABLE: Disabling certificate validation
    HttpClient client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }

  void configureUnsafeHttp() {
    // VULNERABLE: Global override of certificate checking
    HttpOverrides.global = InsecureHttpOverrides();
  }
}

class InsecureHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback =
          (X509Certificate cert, String host, int port) => true;
  }
}

// =============================================================================
// V013: Missing Certificate Pinning (MASVS-NETWORK-2)
// =============================================================================
class NoPinning {
  void makeRequest() {
    // VULNERABLE: No certificate pinning
    final client = http.Client();
    // Using default client without pinning
  }

  void makeDioRequest() {
    // VULNERABLE: Dio without certificate pinning
    final dio = Dio();
    dio.get('https://api.example.com/data');
  }
}

// =============================================================================
// V014: Insecure Deep Link Handling (MASVS-PLATFORM-1)
// =============================================================================
class InsecureDeepLinks {
  void handleDeepLink() {
    // VULNERABLE: Deep link handling without validation
    getInitialLink().then((link) {
      if (link != null) {
        final uri = Uri.parse(link);
        // Directly using parameters without validation
        navigateToPage(uri.queryParameters['page']!);
        performAction(uri.queryParameters['action']!);
      }
    });
  }

  void setupLinkListener() {
    // VULNERABLE: Listening to links without validation
    linkStream.listen((link) {
      processLink(link);
    });
  }
}

// =============================================================================
// V015: WebView with JavaScript Enabled (MASVS-PLATFORM-2)
// =============================================================================
class InsecureWebView extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // VULNERABLE: JavaScript enabled with untrusted content
    return WebView(
      initialUrl: 'https://untrusted-site.com',
      javascriptMode: JavascriptMode.unrestricted,
    );
  }
}

// =============================================================================
// V016: Exposed JavaScript Bridge (MASVS-PLATFORM-2)
// =============================================================================
class ExposedJsBridge {
  late WebViewController controller;

  void setupBridge() {
    // VULNERABLE: Exposing native functionality to JavaScript
    controller.addJavaScriptChannel(
      JavaScriptChannel(
        name: 'NativeBridge',
        onMessageReceived: (message) {
          // Directly executing commands from JavaScript
          executeNativeCommand(message.message);
        },
      ),
    );
  }

  void executeUserScript(String userInput) {
    // VULNERABLE: Executing dynamic JavaScript
    controller.evaluateJavascript('processData("$userInput")');
  }
}

// =============================================================================
// V017: Sensitive UI Not Protected (MASVS-PLATFORM-3)
// =============================================================================
class SensitiveScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // VULNERABLE: No screenshot protection
    return Scaffold(
      body: Column(
        children: [
          TextField(
            obscureText: true,
            decoration: InputDecoration(labelText: 'Password'),
          ),
          TextField(
            decoration: InputDecoration(labelText: 'Credit Card Number'),
            controller: creditCardController,
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// V018: Debug Mode Enabled in Production (MASVS-CODE-4)
// =============================================================================
class DebugConfig {
  // VULNERABLE: Debug mode hardcoded to true
  static const bool debugMode = true;
  static const bool isDebug = true;

  void logDebugInfo() {
    // VULNERABLE: Debug print statements
    debugPrint('Debug: User session data...');
  }
}

// =============================================================================
// V019: SQL Injection Vulnerability (MASVS-CODE-4)
// =============================================================================
class InsecureDatabase {
  late Database db;

  Future<List<Map>> getUserByName(String userName) async {
    // VULNERABLE: SQL injection through string concatenation
    return await db.rawQuery('SELECT * FROM users WHERE name = ' + userName);
  }

  Future<void> deleteUser(String id) async {
    // VULNERABLE: SQL injection
    await db.rawDelete('DELETE FROM users WHERE id = $id');
  }

  Future<void> insertUser(String name, String email) async {
    // VULNERABLE: SQL injection
    await db
        .execute('INSERT INTO users (name, email) VALUES ("$name", "$email")');
  }
}

// =============================================================================
// V020: Vulnerable Third-Party Dependencies (MASVS-CODE-3)
// =============================================================================
// Note: This would be in pubspec.yaml
// dependencies:
//   http: ^0.12.0  # Vulnerable old version
//   dio: ^2.0.0    # Old version with vulnerabilities

// =============================================================================
// V021: Outdated Minimum SDK Version (MASVS-CODE-1)
// =============================================================================
// Note: This would be in android/app/build.gradle
// minSdkVersion 16  # Android 4.1 - lacks modern security features

// =============================================================================
// V022: Missing Root/Jailbreak Detection (MASVS-RESILIENCE-1)
// =============================================================================
class NoRootDetection {
  void accessSecureData() {
    // VULNERABLE: No root/jailbreak detection
    final secureStorage = FlutterSecureStorage();
    secureStorage.read(key: 'encryption_key');
    // Should check for rooted device first
  }
}

// =============================================================================
// V023: Missing App Integrity Verification (MASVS-RESILIENCE-2)
// =============================================================================
class PaymentService {
  // VULNERABLE: No integrity verification for sensitive operations
  void processPayment(double amount) {
    // Should verify app integrity before processing
    chargeCard(amount);
  }
}

class LicenseManager {
  // VULNERABLE: License check without integrity verification
  void licenseCheck() {
    // No app signature verification
    verifyLicense();
  }
}

// =============================================================================
// V024: Missing Code Obfuscation (MASVS-RESILIENCE-3)
// =============================================================================
// Note: Build command without obfuscation
// flutter build apk
// flutter build ios

// =============================================================================
// V025: Excessive Permission Requests (MASVS-PRIVACY-1)
// =============================================================================
class ExcessivePermissions {
  void requestAllPermissions() {
    // VULNERABLE: Requesting more permissions than needed
    Permission.camera.request();
    Permission.microphone.request();
    Permission.location.request();
    Permission.contacts.request();
    Permission.calendar.request();
    Permission.sms.request();
    Permission.storage.request();
    Permission.phone.request();
  }
}

// =============================================================================
// V026: Collection of Persistent Device Identifiers (MASVS-PRIVACY-2)
// =============================================================================
class DeviceTracking {
  Future<void> collectDeviceInfo() async {
    // VULNERABLE: Collecting persistent identifiers
    final deviceInfo = DeviceInfoPlugin();
    final androidInfo = await deviceInfo.androidInfo;
    final androidId = androidInfo.androidId; // Persistent identifier

    // Also vulnerable: IMEI, MAC address
    final imei = await getIMEI();
    final macAddress = await getMacAddress();

    // iOS vulnerable identifier
    final iosInfo = await deviceInfo.iosInfo;
    final vendorId = iosInfo.identifierForVendor;
  }
}

// =============================================================================
// Main function
// =============================================================================
void main() {
  runApp(VulnerableApp());
}

class VulnerableApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vulnerable Flutter App',
      home: Scaffold(
        appBar: AppBar(title: Text('Security Test App')),
        body: Center(
          child:
              Text('This app contains intentional vulnerabilities for testing'),
        ),
      ),
    );
  }
}
