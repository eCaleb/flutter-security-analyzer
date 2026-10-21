"""
Integration tests for configuration file scanning.

V020 (vulnerable dependencies), V021 (outdated minimum SDK) and V024
(missing obfuscation) look for problems in project configuration rather
than in Dart code. These tests run the real SecurityScanner against small
temporary Flutter projects to check that each rule reads the right files,
ignores comments, and that no other rules are applied to those files.

Author: Caleb Elebhose
Module: WB7103/WB7104 MSc Cybersecurity Project
University of Chester
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from core.config import ScannerConfig  # noqa: E402
from core.scanner import SecurityScanner  # noqa: E402


MAIN_DART = "import 'package:flutter/material.dart';\n\nvoid main() => runApp(const SizedBox());\n"


class TestConfigFileScanning(unittest.TestCase):
    """Run the real scanner on temporary projects with configuration files."""

    def setUp(self):
        self.project = Path(tempfile.mkdtemp())
        self.write('lib/main.dart', MAIN_DART)

    def tearDown(self):
        shutil.rmtree(self.project)

    def write(self, relative_path: str, content: str) -> Path:
        file_path = self.project / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding='utf-8')
        return file_path

    def scan(self):
        scanner = SecurityScanner(ScannerConfig())
        return scanner.scan(self.project).findings

    def findings_for(self, rule_id: str, file_name: str):
        return [
            f for f in self.scan()
            if f.vulnerability_id == rule_id and f.file_path.endswith(file_name)
        ]

    # ----- V020: vulnerable dependency versions in pubspec.yaml -----

    def test_v020_flags_old_dependency_in_pubspec(self):
        self.write('pubspec.yaml', 'name: demo\ndependencies:\n  http: ^0.13.5\n')
        findings = self.findings_for('V020', 'pubspec.yaml')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 3)

    def test_v020_ignores_current_dependency_versions(self):
        self.write('pubspec.yaml', 'name: demo\ndependencies:\n  http: ^1.2.0\n  dio: ^5.4.0\n')
        self.assertEqual(self.findings_for('V020', 'pubspec.yaml'), [])

    def test_v020_ignores_packages_with_similar_names(self):
        self.write('pubspec.yaml', 'name: demo\ndependencies:\n  rhttp: ^0.18.0\n  dio_cache: ^2.0.0\n')
        self.assertEqual(self.findings_for('V020', 'pubspec.yaml'), [])

    def test_v020_ignores_commented_dependency(self):
        self.write('pubspec.yaml', 'name: demo\ndependencies:\n  # http: ^0.13.5\n  http: ^1.2.0\n')
        self.assertEqual(self.findings_for('V020', 'pubspec.yaml'), [])

    def test_line_numbers_survive_comment_blanking(self):
        self.write('pubspec.yaml', '# comment\n# comment\nname: demo\ndependencies:\n  dio: ^3.0.10\n')
        findings = self.findings_for('V020', 'pubspec.yaml')
        self.assertEqual([f.line_number for f in findings], [5])

    # ----- V021: outdated minimum SDK in Android and iOS build files -----

    def test_v021_flags_low_min_sdk_in_gradle(self):
        self.write('android/app/build.gradle', 'android {\n  defaultConfig {\n    minSdkVersion 19\n  }\n}\n')
        self.assertEqual(len(self.findings_for('V021', 'build.gradle')), 1)

    def test_v021_flags_low_min_sdk_in_gradle_kts(self):
        self.write('android/app/build.gradle.kts', 'android {\n  defaultConfig {\n    minSdk = 21\n  }\n}\n')
        self.assertEqual(len(self.findings_for('V021', 'build.gradle.kts')), 1)

    def test_v021_ignores_flutter_default_min_sdk(self):
        self.write('android/app/build.gradle', 'android {\n  defaultConfig {\n    minSdkVersion flutter.minSdkVersion\n  }\n}\n')
        self.assertEqual(self.findings_for('V021', 'build.gradle'), [])

    def test_v021_ignores_commented_gradle_line(self):
        self.write('android/app/build.gradle', 'android {\n  defaultConfig {\n    // minSdkVersion 16\n    minSdkVersion 24\n  }\n}\n')
        self.assertEqual(self.findings_for('V021', 'build.gradle'), [])

    def test_v021_flags_old_ios_platform_in_podfile(self):
        self.write('ios/Podfile', "platform :ios, '11.0'\n")
        self.assertEqual(len(self.findings_for('V021', 'Podfile')), 1)

    # ----- V024: release builds without --obfuscate -----

    def test_v024_flags_release_build_without_obfuscation(self):
        self.write('.github/workflows/release.yml', 'jobs:\n  build:\n    steps:\n      - run: flutter build apk --release\n')
        self.assertEqual(len(self.findings_for('V024', 'release.yml')), 1)

    def test_v024_ignores_build_with_obfuscation(self):
        self.write(
            '.github/workflows/release.yml',
            'jobs:\n  build:\n    steps:\n      - run: flutter build appbundle --obfuscate --split-debug-info=build/symbols\n',
        )
        self.assertEqual(self.findings_for('V024', 'release.yml'), [])

    def test_v024_checks_build_scripts(self):
        self.write('build_release.sh', '#!/bin/sh\nflutter build ipa\n')
        self.assertEqual(len(self.findings_for('V024', 'build_release.sh')), 1)

    # ----- Scope of configuration scanning -----

    def test_dart_rules_are_not_applied_to_config_files(self):
        self.write(
            '.github/workflows/release.yml',
            'env:\n  API_KEY: "AIzaFAKEKEYFORTESTINGONLY00000000000"\n',
        )
        config_findings = [f for f in self.scan() if f.file_path.endswith('release.yml')]
        self.assertEqual(config_findings, [])

    def test_single_file_scan_does_not_read_config_files(self):
        self.write('pubspec.yaml', 'name: demo\ndependencies:\n  http: ^0.13.5\n')
        scanner = SecurityScanner(ScannerConfig())
        findings = scanner.scan(self.project / 'lib' / 'main.dart').findings
        self.assertEqual([f for f in findings if f.vulnerability_id == 'V020'], [])


if __name__ == '__main__':
    unittest.main()
