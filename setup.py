from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='entra-oauth-consent-auditor',
    version='0.1.0',
    description='Read-only CLI to audit OAuth consents and risky Microsoft Graph permissions in Microsoft Entra.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='OrygnsCode',
    author_email='admin@orygns.com',
    url='https://github.com/OrygnsCode/Entra-OAuth-Consent-Auditor',
    packages=find_packages(),
    install_requires=[
        'msal>=1.20.0',
        'requests>=2.28.0',
        'python-dotenv>=1.0.0',
        'rich>=13.0.0',
    ],
    entry_points={
        'console_scripts': [
            'entra-oauth-consent-auditor=entra_oauth_consent_auditor.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
    ],
    python_requires='>=3.9',
)
