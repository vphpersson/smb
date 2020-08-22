from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional, Type
from struct import pack, unpack_from

from msdsalgs.fscc.file_information import FileAttributes, FileInformation

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import MalformedCloseRequestError, \
    NonEmptyCloseRequestReservedValueError, InvalidCloseFlagValueError, MalformedCloseResponseError, \
    InvalidCloseResponseFlagValueError, NonEmptyCloseResponseReservedValueError, \
    InvalidCloseResponseFileAttributesValueError, NonEmptyCloseResponseCreationTimeValueError, \
    NonEmptyCloseResponseLastAccessTimeValueError, NonEmptyCloseResponseLastWriteTimeValueError, \
    NonEmptyCloseResponseChangeTimeValueError, NonEmptyCloseResponseAllocationSizeValueError, \
    NonEmptyCloseResponseEndofFileValueError, NonEmptyCloseResponseFileAttributesValueError, MalformedSMBv2MessageError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.close_flag_mask import CloseFlag


@dataclass
@Message.register
class CloseResponse(ResponseMessage):
    flags: CloseFlag
    file_information: Optional[FileInformation] = None

    STRUCTURE_SIZE: ClassVar[int] = 60
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedCloseResponseError
    _RESERVED: ClassVar[bytes] = bytes(4)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> CloseResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        try:
            flags = CloseFlag.from_int(unpack_from('<H', buffer=body_data, offset=2)[0])
        except ValueError as e:
            raise InvalidCloseFlagValueError(
                message_header='Bad close flag value.',
                observed_value=str(e),
                expected_label='Expected combination of',
                expected_value=','.join(CloseFlag)
            ) from e

        if (reserved := bytes(body_data[4:8])) != cls._RESERVED:
            raise NonEmptyCloseResponseReservedValueError(observed_reserved_value=reserved)

        creation_time: int = unpack_from('<Q', buffer=body_data, offset=8)[0]
        last_access_time: int = unpack_from('<Q', buffer=body_data, offset=16)[0]
        last_write_time: int = unpack_from('<Q', buffer=body_data, offset=24)[0]
        change_time: int = unpack_from('<Q', buffer=body_data, offset=32)[0]
        allocation_size: int = unpack_from('<Q', buffer=body_data, offset=40)[0]
        endof_file: int = unpack_from('<Q', buffer=body_data, offset=48)[0]
        file_attributes_int_value: int = unpack_from('<I', buffer=body_data, offset=56)[0]

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
        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<H', int(self.flags)),
            self._RESERVED,
            bytes(
                self.file_information if self.flags.postquery_attrib else FileInformation.structure_size
            )
        ])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@Message.register
class CloseRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 24
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CLOSE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedCloseRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = CloseResponse
    _RESERVED: ClassVar[bytes] = bytes(4)

    flags: CloseFlag
    file_id: FileId

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> CloseRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        try:
            flags = CloseFlag.from_int(unpack_from('<H', buffer=body_data, offset=2)[0])
        except ValueError as e:
            raise InvalidCloseFlagValueError(
                message_header='Bad close request flag value.',
                observed_value=str(e),
                expected_label='Expected combination of',
                expected_value=','.join(CloseFlag)
            ) from e

        if (reserved := bytes(body_data[4:8])) != cls._RESERVED:
            raise NonEmptyCloseRequestReservedValueError(observed_reserved_value=reserved)

        return cls(header=header, flags=flags, file_id=FileId.from_bytes(data=body_data, base_offset=8))

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<H', int(self.flags)),
            self._RESERVED,
            bytes(self.file_id)
        ])
