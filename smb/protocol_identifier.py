from enum import Enum


class ProtocolIdentifier(Enum):
    SMB_VERSION_1 = b'\xffSMB'
    SMB_VERSION_2 = b'\xfeSMB'
