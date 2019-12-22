from setuptools import setup, find_packages
setup(
    name='smb',
    version='0.1',
    packages=find_packages(),
    dependency_links=[
        'http://github.com/vphpersson/msdsalgs/tarball/master#egg=msdsalgs',
        'http://github.com/vphpersson/ntlm/tarball/master#egg=ntlm',
        'http://github.com/vphpersson/spnego/tarball/master#egg=spnego',
        'http://github.com/vphpersson/asn1/tarball/master#egg=asn1'
    ],
    install_requires=[
        'msdsalgs',
        'ntlm',
        'spnego',
        'asn1'
    ],
)
