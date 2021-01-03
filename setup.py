from setuptools import setup, find_packages

setup(
    name='smb',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'msdsalgs @ git+ssh://git@github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
        'ntlm @ git+ssh://git@github.com/vphpersson/ntlm.git#egg=ntlm',
        'spnego @ git+ssh://git@github.com/vphpersson/spnego.git#egg=spnego',
        'asn1 @ git+ssh://git@github.com/vphpersson/asn1.git#egg=asn1'
    ]
)
