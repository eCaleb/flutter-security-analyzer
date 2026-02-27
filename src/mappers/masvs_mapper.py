"""
MASVS Mapper Module

Maps vulnerabilities to OWASP MASVS v2.1.0 compliance categories and controls.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MasvsControl:
    """Represents an OWASP MASVS control."""
    control_id: str
    title: str
    description: str
    level: int  # L1 or L2
    

@dataclass
class MasvsCategory:
    """Represents an OWASP MASVS category."""
    category_id: str
    name: str
    description: str
    controls: List[MasvsControl]


class MasvsMapper:
    """
    Maps findings to OWASP MASVS v2.1.0 compliance framework.
    
    This class provides mapping between detected vulnerabilities and
    the MASVS standard, enabling compliance reporting.
    """
    
    def __init__(self):
        """Initialize the mapper with MASVS v2.1.0 definitions."""
        self.categories = self._load_masvs_definitions()
    
    def _load_masvs_definitions(self) -> Dict[str, MasvsCategory]:
        """Load MASVS v2.1.0 category and control definitions."""
        return {
            'STORAGE': MasvsCategory(
                category_id='MASVS-STORAGE',
                name='Data Storage',
                description='Secure storage of sensitive data on the device.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-STORAGE-1',
                        title='Secure Storage of Sensitive Data',
                        description='The app securely stores sensitive data.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-STORAGE-2',
                        title='Prevention of Data Leakage',
                        description='The app prevents leakage of sensitive data.',
                        level=1
                    ),
                ]
            ),
            'CRYPTO': MasvsCategory(
                category_id='MASVS-CRYPTO',
                name='Cryptography',
                description='Use of cryptography to protect sensitive data.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-CRYPTO-1',
                        title='Use of Strong Cryptography',
                        description='The app employs current strong cryptography and uses it according to industry best practices.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-CRYPTO-2',
                        title='Secure Key Management',
                        description='The app performs key management according to industry best practices.',
                        level=1
                    ),
                ]
            ),
            'AUTH': MasvsCategory(
                category_id='MASVS-AUTH',
                name='Authentication and Authorization',
                description='Authentication and session management mechanisms.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-AUTH-1',
                        title='Secure Authentication',
                        description='The app uses secure authentication and authorization protocols.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-AUTH-2',
                        title='Local Authentication',
                        description='The app securely implements local authentication.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-AUTH-3',
                        title='Session Management',
                        description='The app securely manages user sessions.',
                        level=1
                    ),
                ]
            ),
            'NETWORK': MasvsCategory(
                category_id='MASVS-NETWORK',
                name='Network Communication',
                description='Secure network communication.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-NETWORK-1',
                        title='Secure Network Communication',
                        description='The app secures all network traffic according to current best practices.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-NETWORK-2',
                        title='TLS Configuration',
                        description='The app performs identity pinning for all remote endpoints under the developers control.',
                        level=2
                    ),
                ]
            ),
            'PLATFORM': MasvsCategory(
                category_id='MASVS-PLATFORM',
                name='Platform Interaction',
                description='Secure use of platform APIs and components.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-PLATFORM-1',
                        title='Secure IPC',
                        description='The app uses IPC mechanisms securely.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-PLATFORM-2',
                        title='WebView Security',
                        description='The app uses WebViews securely.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-PLATFORM-3',
                        title='Permission Management',
                        description='The app uses the principle of least privilege for permissions.',
                        level=1
                    ),
                ]
            ),
            'CODE': MasvsCategory(
                category_id='MASVS-CODE',
                name='Code Quality',
                description='Security best practices for code quality.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-CODE-1',
                        title='Input Validation',
                        description='The app validates and sanitizes all untrusted inputs.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-CODE-2',
                        title='Secure Data Handling',
                        description='The app handles data securely.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-CODE-3',
                        title='Secure Coding Practices',
                        description='The app follows secure coding practices.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-CODE-4',
                        title='Testing and Debugging',
                        description='The app does not expose testing/debugging functionality in production.',
                        level=1
                    ),
                ]
            ),
            'RESILIENCE': MasvsCategory(
                category_id='MASVS-RESILIENCE',
                name='Resilience Against Reverse Engineering',
                description='Defense-in-depth measures against reverse engineering.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-RESILIENCE-1',
                        title='Root/Jailbreak Detection',
                        description='The app detects and responds to running on a rooted or jailbroken device.',
                        level=2
                    ),
                    MasvsControl(
                        control_id='MASVS-RESILIENCE-2',
                        title='Anti-Debugging',
                        description='The app implements anti-debugging techniques.',
                        level=2
                    ),
                    MasvsControl(
                        control_id='MASVS-RESILIENCE-3',
                        title='Code Obfuscation',
                        description='The app implements code obfuscation.',
                        level=2
                    ),
                    MasvsControl(
                        control_id='MASVS-RESILIENCE-4',
                        title='Integrity Verification',
                        description='The app implements integrity verification.',
                        level=2
                    ),
                ]
            ),
            'PRIVACY': MasvsCategory(
                category_id='MASVS-PRIVACY',
                name='Privacy',
                description='Protection of user privacy.',
                controls=[
                    MasvsControl(
                        control_id='MASVS-PRIVACY-1',
                        title='Data Minimization',
                        description='The app minimizes access to sensitive data and resources.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-PRIVACY-2',
                        title='Data Collection Transparency',
                        description='The app is transparent about data collection.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-PRIVACY-3',
                        title='User Consent',
                        description='The app obtains proper user consent for data collection.',
                        level=1
                    ),
                    MasvsControl(
                        control_id='MASVS-PRIVACY-4',
                        title='Privacy Controls',
                        description='The app provides privacy controls to users.',
                        level=1
                    ),
                ]
            ),
        }
    
    def get_category(self, category_id: str) -> Optional[MasvsCategory]:
        """Get a MASVS category by ID."""
        return self.categories.get(category_id)
    
    def get_control(self, control_id: str) -> Optional[MasvsControl]:
        """Get a MASVS control by full control ID (e.g., 'MASVS-STORAGE-1')."""
        parts = control_id.split('-')
        if len(parts) < 3:
            return None
        
        category_id = parts[1]
        category = self.categories.get(category_id)
        
        if not category:
            return None
        
        for control in category.controls:
            if control.control_id == control_id:
                return control
        
        return None
    
    def get_compliance_summary(self, findings: list) -> Dict:
        """
        Generate a compliance summary based on findings.
        
        Args:
            findings: List of Finding objects
            
        Returns:
            Dictionary with compliance status by category and control
        """
        summary = {}
        
        for category_id, category in self.categories.items():
            category_findings = [f for f in findings if f.masvs_category == category_id]
            
            control_status = {}
            for control in category.controls:
                control_findings = [f for f in category_findings if f.masvs_control == control.control_id]
                control_status[control.control_id] = {
                    'title': control.title,
                    'level': control.level,
                    'findings_count': len(control_findings),
                    'status': 'FAIL' if control_findings else 'PASS',
                    'severity_breakdown': {
                        'critical': sum(1 for f in control_findings if f.severity == 'critical'),
                        'high': sum(1 for f in control_findings if f.severity == 'high'),
                        'medium': sum(1 for f in control_findings if f.severity == 'medium'),
                        'low': sum(1 for f in control_findings if f.severity == 'low'),
                        'info': sum(1 for f in control_findings if f.severity == 'info'),
                    }
                }
            
            summary[category_id] = {
                'name': category.name,
                'description': category.description,
                'findings_count': len(category_findings),
                'status': 'FAIL' if category_findings else 'PASS',
                'controls': control_status
            }
        
        return summary
