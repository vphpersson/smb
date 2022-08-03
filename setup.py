from setuptools import setup, find_packages

setup(
    name='smb',
    version='0.11',
    packages=find_packages(),
    install_requires=[
        'msdsalgs @ git+https://github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
        'ntlm @ git+https://github.com/vphpersson/ntlm.git#egg=ntlm',
        'spnego @ git+https://github.com/vphpersson/spnego.git#egg=spnego',
        'asn1 @ git+https://github.com/vphpersson/asn1.git#egg=asn1'
    ]
)
