from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.fscc.file_information import FileAttributes, FileInformation

from smb.v2.messages import RequestMessage, ResponseMessage, register_smbv2_message
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedCloseRequestError, \
    NonEmptyCloseRequestReservedValueError, InvalidCloseRequestFlagValueError, MalformedCloseResponseError, \
    InvalidCloseResponseFlagValueError, NonEmptyCloseResponseReservedValueError, \
    InvalidCloseResponseFileAttributesValueError, NonEmptyCloseResponseCreationTimeValueError, \
    NonEmptyCloseResponseLastAccessTimeValueError, NonEmptyCloseResponseLastWriteTimeValueError, \
    NonEmptyCloseResponseChangeTimeValueError, NonEmptyCloseResponseAllocationSizeValueError, \
    NonEmptyCloseResponseEndofFileValueError, NonEmptyCloseResponseFileAttributesValueError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.close_flag_mask import CloseFlag


@dataclass
@register_smbv2_message
class CloseResponse(ResponseMessage):
    flags: CloseFlag
    file_information: Optional[FileInformation] = None

    STRUCTURE_SIZE: ClassVar[int] = 60
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    _RESERVED: ClassVar[bytes] = bytes(4)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> CloseResponse:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCloseResponseError(str(e)) from e

        try:
            flags = CloseFlag.from_int(struct_unpack('<H', body_data[2:4])[0])
        except ValueError as e:
            raise InvalidCloseResponseFlagValueError(str(e)) from e

        reserved: bytes = body_data[4:8]
        if reserved != cls._RESERVED:
            raise NonEmptyCloseResponseReservedValueError(observed_reserved_value=reserved)

        creation_time: int = struct_unpack('<Q', body_data[8:16])[0]
        last_access_time: int = struct_unpack('<Q', body_data[16:24])[0]
        last_write_time: int = struct_unpack('<Q', body_data[24:32])[0]
        change_time: int = struct_unpack('<Q', body_data[32:40])[0]
        allocation_size: int = struct_unpack('<Q', body_data[40:48])[0]
        endof_file: int = struct_unpack('<Q', body_data[48:56])[0]
        file_attributes_int_value: int = struct_unpack('<I', body_data[56:60])[0]

        try:
            file_attributes = FileAttributes.from_int(file_attributes_int_value)
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
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<H', int(self.flags)),
            self._RESERVED,
            attributes_chunk
        ])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@register_smbv2_message
class CloseRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 24
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = CloseResponse
    _RESERVED: ClassVar[bytes] = bytes(4)

    flags: CloseFlag
    file_id: FileId

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> CloseRequest:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCloseRequestError(str(e)) from e

        try:
            flags = CloseFlag.from_int(struct_unpack('<H', body_data[2:4])[0])
        except ValueError as e:
            raise InvalidCloseRequestFlagValueError(str(e)) from e

        reserved = body_data[4:8]
        if reserved != cls._RESERVED:
            raise NonEmptyCloseRequestReservedValueError(observed_reserved_value=reserved)

        return cls(header=header, flags=flags, file_id=FileId.from_bytes(data=body_data[8:24]))

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<H', int(self.flags)),
            self._RESERVED,
            bytes(self.file_id)
        ])