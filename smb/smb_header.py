from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass

from smb.protocol_identifier import ProtocolIdentifier


@dataclass
class SMBHeader(ABC):

    @staticmethod
    @abstractmethod
    def protocol_identifier() -> ProtocolIdentifier:
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass

    @classmethod
    def from_bytes(cls, data: bytes, **version_specific_options) -> SMBHeader:
        from smb.v1.smbv1_header import SMBv1Header
        from smb.v2.smbv2_header import SMBv2Header

        protocol_identifier = ProtocolIdentifier(data[:4])

        if protocol_identifier is ProtocolIdentifier.SMB_VERSION_1:
            return SMBv1Header.from_bytes(data=data)
        elif protocol_identifier is ProtocolIdentifier.SMB_VERSION_2:
            return SMBv2Header._from_bytes(data=data, **version_specific_options)
        else:
            # TODO: Use proper exception.
            raise ValueError
