from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.fscc.file_information import FileInformation

from smb.v2.messages.message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.messages.create.create_request import FileAttributes
from smb.v2.messages.close.close_request import CloseFlag
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedCloseResponseError, \
    InvalidCloseResponseFlagValueError, NonEmptyCloseResponseReservedValueError, \
    InvalidCloseResponseFileAttributesValueError, NonEmptyCloseResponseCreationTimeValueError, \
    NonEmptyCloseResponseLastAccessTimeValueError, NonEmptyCloseResponseLastWriteTimeValueError, \
    NonEmptyCloseResponseChangeTimeValueError, NonEmptyCloseResponseAllocationSizeValueError, \
    NonEmptyCloseResponseEndofFileValueError, NonEmptyCloseResponseFileAttributesValueError


@dataclass
@register_smbv2_message
class CloseResponse(SMBv2ResponseMessage):
    flags: CloseFlag
    file_information: Optional[FileInformation] = None

    structure_size: ClassVar[int] = 60
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    _reserved: ClassVar[bytes] = 4 * b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> CloseResponse:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCloseResponseError(str(e)) from e

        try:
            flags = CloseFlag.from_mask(struct_unpack('<H', body_data[2:4])[0])
        except ValueError as e:
            raise InvalidCloseResponseFlagValueError(str(e)) from e

        reserved: bytes = body_data[4:8]
        if reserved != cls._reserved:
            raise NonEmptyCloseResponseReservedValueError(observed_reserved_value=reserved)

        creation_time: int = struct_unpack('<Q', body_data[8:16])[0]
        last_access_time: int = struct_unpack('<Q', body_data[16:24])[0]
        last_write_time: int = struct_unpack('<Q', body_data[24:32])[0]
        change_time: int = struct_unpack('<Q', body_data[32:40])[0]
        allocation_size: int = struct_unpack('<Q', body_data[40:48])[0]
        endof_file: int = struct_unpack('<Q', body_data[48:56])[0]
        file_attributes_int_value: int = struct_unpack('<I', body_data[56:60])[0]

        try:
            file_attributes = FileAttributes.from_mask(file_attributes_int_value)
        except ValueError as e:
            raise InvalidCloseResponseFileAttributesValueError(str(e)) from e

        if flags.postquery_attrib:
            return cls(
                header=header,
                flags=flags,
                file_information=FileInformation(
                    _creation_time=creation_time,
                    _last_access_time=last_access_time,
                    _last_write_time=last_write_time,
                    _change_time=change_time,
                    allocation_size=allocation_size,
                    endof_file=endof_file,
                    file_attributes=file_attributes
                )
            )
        else:
            if creation_time != 0:
                raise NonEmptyCloseResponseCreationTimeValueError

            if last_access_time != 0:
                raise NonEmptyCloseResponseLastAccessTimeValueError

            if last_write_time != 0:
                raise NonEmptyCloseResponseLastWriteTimeValueError

            if change_time != 0:
                raise NonEmptyCloseResponseChangeTimeValueError

            if allocation_size != 0:
                raise NonEmptyCloseResponseAllocationSizeValueError

            if endof_file != 0:
                raise NonEmptyCloseResponseEndofFileValueError

            if file_attributes_int_value != 0:
                raise NonEmptyCloseResponseFileAttributesValueError

            return cls(header=header, flags=flags, file_information=None)

    def __bytes__(self) -> bytes:

        attributes_chunk = (
            bytes(self.file_information) if self.flags.postquery_attrib
            else FileInformation.structure_size * b'\x00'
        )

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<H', self.flags.to_mask()),
            self._reserved,
            attributes_chunk
        ])

    def __len__(self) -> int:
        return len(self.header) + self.structure_size
