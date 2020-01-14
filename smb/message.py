from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional

from smb.header import Header


@dataclass
class Message(ABC):
    header: Header

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        version_specific_header_options: Optional[Dict[str, Any]] = None
    ) -> Message:

        from smb.v1.smbv1_header import SMBv1Header
        from smb.v1.smbv1_message import SMBv1Message
        from smb.v2.header import Header
        from smb.v2.messages import Message

        version_specific_header_options = version_specific_header_options or {}

        smb_header = Header.from_bytes(data=data, **version_specific_header_options)

        if isinstance(smb_header, SMBv1Header):
            return SMBv1Message.from_bytes_and_header(data=data, header=smb_header)
        elif isinstance(smb_header, Header):
            return Message.from_bytes_and_header(data=data, header=smb_header)
        else:
            # TODO: Use proper exception.
            raise ValueError

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass
#
#
# class SMBRequestMessage(ABC):
#     pass
#
#
# class SMBResponseMessage(ABC):
#     pass
