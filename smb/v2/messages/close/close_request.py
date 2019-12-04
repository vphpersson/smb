from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntFlag

from msdsalgs.utils import make_mask_class

from smb.v2.messages.message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedCloseRequestError, \
    NonEmptyCloseRequestReservedValueError, InvalidCloseRequestFlagValueError
from smb.v2.file_id import FileId


class CloseFlagMask(IntFlag):
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001


CloseFlag = make_mask_class(CloseFlagMask, prefix='SMB2_CLOSE_FLAG_')


@dataclass
@register_smbv2_message
class CloseRequest(SMBv2RequestMessage):

    flags: CloseFlag
    file_id: FileId

    structure_size: ClassVar[int] = 24
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    _reserved: ClassVar[bytes] = 4 * b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> CloseRequest:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCloseRequestError(str(e)) from e

        try:
            flags = CloseFlag.from_mask(struct_unpack('<H', body_data[2:4])[0])
        except ValueError as e:
            raise InvalidCloseRequestFlagValueError(str(e)) from e

        reserved = body_data[4:8]
        if reserved != cls._reserved:
            raise NonEmptyCloseRequestReservedValueError(observed_reserved_value=reserved)

        return cls(header=header, flags=flags, file_id=FileId.from_bytes(data=body_data[8:24]))

    def __len__(self) -> int:
        return len(self.header) + self.structure_size

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<H', self.flags.to_mask()),
            self._reserved,
            bytes(self.file_id)
        ])
