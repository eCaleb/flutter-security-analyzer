"""
Setup script for Flutter Security Scanner.
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='flutter-security-scanner',
    version='1.0.0',
    author='Caleb Elebhose',
    author_email='caleb.elebhose@chester.ac.uk',
    description='Static security analysis tool for Flutter/Dart applications with MASVS compliance mapping',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/calebelebhose/flutter-security-scanner',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    python_requires='>=3.9',
    install_requires=[],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'flutter-security-scanner=main:main',
        ],
    },
    keywords='flutter dart security scanner masvs owasp static-analysis',
    project_urls={
        'Bug Reports': 'https://github.com/calebelebhose/flutter-security-scanner/issues',
        'Source': 'https://github.com/calebelebhose/flutter-security-scanner',
    },
)
