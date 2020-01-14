from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class Header(ABC):

    PROTOCOL_IDENTIFIER: ClassVar[bytes] = NotImplemented

    @abstractmethod
    def __len__(self) -> int:
        pass

    @classmethod
    def from_bytes(cls, data: bytes, **version_specific_options) -> Header:
        from smb.v1.smbv1_header import SMBv1Header
        from smb.v2.header import Header

        protocol_identifier = data[:4]

        if protocol_identifier == SMBv1Header.PROTOCOL_IDENTIFIER:
            return SMBv1Header.from_bytes(data=data)
        elif protocol_identifier == Header.PROTOCOL_IDENTIFIER:
            return Header._from_bytes(data=data, **version_specific_options)
        else:
            # TODO: Use proper exception.
            raise ValueError
