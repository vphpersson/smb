from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack

from smb.smb_message import SMBResponseMessage
from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError


@dataclass
@register_smbv2_message
class WriteResponse(SMBv2Message, SMBResponseMessage):

    structure_size: ClassVar[int] = 17

    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE

    _reserved: ClassVar[bytes] = bytes(2)
    _reserved_remaining: ClassVar[bytes] = bytes(4)
    _reserved_write_channel_info_offset: ClassVar[bytes] = bytes(2)
    _reserved_write_channel_info_length: ClassVar[bytes] = bytes(2)

    count: int

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> WriteResponse:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_bytes[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        reserved_bytes: bytes = body_bytes[2:4]
        if reserved_bytes != cls._reserved:
            # TODO: Use proper exception.
            raise ValueError

        remaining_bytes: bytes = body_bytes[8:12]
        if remaining_bytes != cls._reserved_remaining:
            # TODO: Use proper exception.
            raise ValueError

        write_channel_info_offset_bytes: bytes = body_bytes[12:14]
        if write_channel_info_offset_bytes != cls._reserved_write_channel_info_offset:
            # TODO: Use proper exception.
            raise ValueError

        write_channel_info_length_bytes: bytes = body_bytes[14:16]
        if write_channel_info_length_bytes != cls._reserved_write_channel_info_length:
            # TODO: Use proper exception.
            raise ValueError

        return cls(header=header, count=struct_unpack('<I', body_bytes[4:8])[0])

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            self._reserved,
            struct_pack('<I', self.count),
            self._reserved_remaining,
            self._reserved_write_channel_info_offset,
            self._reserved_write_channel_info_length
        ])

    def __len__(self) -> int:
        return self.header.structure_size + self.structure_size
