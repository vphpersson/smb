from setuptools import setup, find_packages

setup(
    name='smb',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'msdsalgs @ http://github.com/vphpersson/msdsalgs/tarball/master',
        'ntlm @ http://github.com/vphpersson/ntlm/tarball/master',
        'spnego @ http://github.com/vphpersson/spnego/tarball/master',
        'asn1 @ http://github.com/vphpersson/asn1/tarball/master'
    ]
)
