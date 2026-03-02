# Flutter Security Scanner

A static analysis tool for detecting security vulnerabilities in Flutter/Dart applications with OWASP MASVS v2.1.0 compliance mapping.

## 🎓 Academic Project

This tool is developed as part of an MSc Cybersecurity final year project at the University of Chester.

**Author:** Caleb Elebhose  
**Supervisor:** Dr. Bismark Asare  
**Module:** WB7103/WB7104

## 🔍 Features

- **Pattern-Based Detection**: Regex-based vulnerability detection for Dart code
- **MASVS Compliance Mapping**: All findings mapped to OWASP MASVS v2.1.0 controls
- **Multiple Output Formats**: Console, JSON, and HTML reports
- **CI/CD Integration**: Exit codes suitable for pipeline integration
- **26+ Vulnerability Patterns**: Covering all 8 MASVS categories

## 📋 MASVS Categories Covered

| Category | Description | Patterns |
|----------|-------------|----------|
| STORAGE | Data storage security | 5 |
| CRYPTO | Cryptographic implementations | 4 |
| AUTH | Authentication and authorization | 4 |
| NETWORK | Network communication security | 4 |
| PLATFORM | Platform interaction security | 4 |
| CODE | Code quality and injection prevention | 5 |
| RESILIENCE | Anti-reverse engineering | 4 |
| PRIVACY | User privacy protection | 4 |

## 🚀 Installation

```
bash
# Clone the repository
git clone https://github.com/calebelebhose/flutter-security-scanner.git
cd flutter-security-scanner

# Install dependencies (optional - for development)
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

## 📖 Usage

### Basic Scan

```
bash
python src/main.py /path/to/flutter/project
```

### Output Formats

```
bash
# Console output (default)
python src/main.py ./my_flutter_app

# JSON output
python src/main.py ./my_flutter_app -f json -o results.json

# HTML report
python src/main.py ./my_flutter_app -f html -o report.html
```

### Filter by Severity

```
bash
# Only show high and critical findings
python src/main.py ./my_flutter_app -s high
```

### Filter by MASVS Category

```
bash
# Only scan for STORAGE and CRYPTO issues
python src/main.py ./my_flutter_app --masvs-category STORAGE CRYPTO
```

### Verbose Mode

```
bash
python src/main.py ./my_flutter_app -v
```

## 🔧 CI/CD Integration

### Exit Codes

- `0`: No high or critical findings
- `1`: High severity findings detected
- `2`: Critical findings detected

### GitHub Actions Example

```
yaml
- name: Security Scan
  run: |
    pip install flutter-security-scanner
    flutter-security-scanner ./lib -f json -o security-results.json
```

### Docker

```
bash
docker run -v $(pwd):/app flutter-security-scanner /app
```

## 📁 Project Structure

```
flutter-security-scanner/
├── src/
│   ├── main.py              # CLI entry point
│   ├── core/
│   │   ├── scanner.py       # Main scanner logic
│   │   └── config.py        # Configuration handling
│   ├── patterns/
│   │   ├── base_pattern.py  # Pattern base class
│   │   ├── pattern_registry.py
│   │   ├── storage_patterns.py
│   │   ├── crypto_patterns.py
│   │   ├── auth_patterns.py
│   │   ├── network_patterns.py
│   │   ├── platform_patterns.py
│   │   ├── code_patterns.py
│   │   ├── resilience_patterns.py
│   │   └── privacy_patterns.py
│   ├── mappers/
│   │   └── masvs_mapper.py  # MASVS compliance mapping
│   └── reporters/
│       ├── console_reporter.py
│       ├── json_reporter.py
│       └── html_reporter.py
├── tests/
├── docs/
├── samples/
├── .github/workflows/
├── requirements.txt
├── setup.py
└── README.md
```

## 🧪 Testing

```
bash
# Run all tests
pytest

# With coverage
pytest --cov=src tests/
```

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgements

- OWASP Mobile Application Security Project
- University of Chester Cybersecurity Department


## 📚 References

- [OWASP MASVS v2.1.0](https://mas.owasp.org/MASVS/)
- [OWASP Mobile Security Testing Guide](https://mas.owasp.org/MSTG/)
- [Flutter Security Documentation](https://flutter.dev/security)
