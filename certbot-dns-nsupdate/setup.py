import os
from setuptools import setup, find_packages

version = '0.1.0'

setup(
    name='certbot-dns-nsupdate',
    version=version,
    description='Certbot DNS authenticator using nsupdate with Kerberos (GSS-TSIG, RFC 3645)',
    url='https://github.com/anomalyco/certmate',
    author='CertMate',
    license='Apache-2.0',
    python_requires='>=3.9',
    packages=find_packages(),
    install_requires=[
        'certbot>=2.0.0',
        'setuptools',
    ],
    entry_points={
        'certbot.plugins': [
            'dns-nsupdate = certbot_dns_nsupdate._internal.dns_nsupdate:Authenticator',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: Kerberos',
        'Topic :: Security :: Cryptography',
    ],
)
