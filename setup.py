from setuptools import setup, find_packages
setup(
    name='smb',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'msdsalgs',
        'ntlm',
        'spnego',
        'asn1'
    ],
    dependency_links=[
        'git+https://github.com/vphpersson/msdsalgs#egg=msdsalgs',
        'git+https://github.com/vphpersson/ntlm#egg=ntlm',
        'git+https://github.com/vphpersson/spnego#egg=spnego',
        'git+https://github.com/vphpersson/asn1#egg=asn1'
    ]
)
