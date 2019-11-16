from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.smbv2_message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedReadResponseError, \
    NonEmptyReadResponseReservedValueError, NonEmptyReadResponseReserved2ValueError


@dataclass
@register_smbv2_message
class ReadResponse(SMBv2ResponseMessage):
    buffer: bytes
    data_remaining_length: int

    structure_size: ClassVar[int] = 17
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    _reserved: ClassVar[bytes] = b'\x00'
    _reserved_2: ClassVar[bytes] = 4 * b'\x00'

    @property
    def data_length(self) -> int:
        return len(self.buffer)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> ReadResponse:

        body_data = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedReadResponseError(str(e)) from e

        # TODO: The docs says that it should be ignored by the client; use strict mode?
        reserved = body_data[3:4]
        if reserved != cls._reserved:
            raise NonEmptyReadResponseReservedValueError(observed_reserved_value=reserved)

        reserved_2 = body_data[12:16]
        if reserved_2 != cls._reserved_2:
            raise NonEmptyReadResponseReserved2ValueError(observed_reserved_2_value=reserved_2)

        data_offset: int = struct_unpack('<B', body_data[2:3])[0]
        data_length: int = struct_unpack('<I', body_data[4:8])[0]

        return cls(
            header=header,
            data_remaining_length=struct_unpack('<I', body_data[8:12])[0],
            buffer=data[data_offset:data_offset+data_length]
        )

    def __bytes__(self) -> bytes:

        data_offset = len(self.header) + self.structure_size - 1

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<B', data_offset),
            self._reserved,
            struct_pack('<I', len(self.buffer)),
            struct_pack('<I', self.data_remaining_length),
            self._reserved_2,
            self.buffer
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.structure_size - 1) + len(self.buffer)






