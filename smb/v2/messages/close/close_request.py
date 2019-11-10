from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntFlag

from smb.v2.smbv2_message import SMBv2Message
from smb.v2.smbv2_header import SMBv2Header
from smb.exceptions import IncorrectStructureSizeError, MalformedCloseRequestError, \
    NonEmptyCloseRequestReservedValueError, InvalidCloseRequestFlagValueError
from smb.v2.file_id import FileId

from msdsalgs.utils import make_mask_class


class CloseFlagMask(IntFlag):
    # NOTE: Not actually part of the flag.
    SMB2_CLOSE_FLAG_NONE = 0x00
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001


CloseFlag = make_mask_class(CloseFlagMask, prefix='SMB2_CLOSE_FLAG_')


@dataclass
class CloseRequest(SMBv2Message):

    flags: CloseFlag
    file_id: FileId

    structure_size: ClassVar[int] = 24
    _reserved: ClassVar[bytes] = 4 * b'\x00'

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> CloseRequest:
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
