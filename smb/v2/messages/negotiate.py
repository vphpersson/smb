from __future__ import annotations
from dataclasses import dataclass
from uuid import UUID
from typing import Tuple, Optional, ClassVar, Type
from abc import ABC
from struct import unpack as struct_unpack, pack as struct_pack
from datetime import datetime

from msdsalgs.time import filetime_to_datetime

from smb.v2.header import Header, SMBv2Command
from smb.v2.messages import Message, ResponseMessage, RequestMessage
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.security_mode import SecurityMode
from smb.v2.structures.capabilities import CapabilitiesFlag
from smb.v2.structures.negotiate_context import NegotiateContextList
from smb.exceptions import MalformedNegotiateRequestError,\
    NoNegotiateDialectsError, NegotiateRequestCapabilitiesNotEmpty, NotImplementedNegotiateRequestError, \
    MalformedNegotiateResponseError, MalformedSMBv2MessageError


@dataclass
@Message.register
class NegotiateResponse(ResponseMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 65
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_NEGOTIATE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedNegotiateResponseError

    dialect_revision: Dialect
    security_mode: SecurityMode
    server_guid: UUID
    capabilities: CapabilitiesFlag
    max_transact_size: int
    max_read_size: int
    max_write_size: int
    _system_time: int
    _server_start_time: int
    security_buffer: bytes

    @property
    def system_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._system_time)

    @property
    def server_start_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._server_start_time)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> NegotiateResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        dialect_revision = Dialect(struct_unpack('<H', body_data[4:6])[0])
        security_buffer_offset: int = struct_unpack('<H', body_data[56:58])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[58:60])[0]

        base_kwargs = dict(
            header=header,
            dialect_revision=dialect_revision,
            security_mode=SecurityMode(struct_unpack('<H', body_data[2:4])[0]),
            server_guid=UUID(bytes=body_data[8:24]),
            capabilities=CapabilitiesFlag.from_int(struct_unpack('<I', body_data[24:28])[0]),
            max_transact_size=struct_unpack('<I', body_data[28:32])[0],
            max_read_size=struct_unpack('<I', body_data[32:36])[0],
            max_write_size=struct_unpack('<I', body_data[36:40])[0],
            _system_time=struct_unpack('<Q', data[40:48])[0],
            _server_start_time=struct_unpack('<Q', data[48:56])[0],
            security_buffer=data[security_buffer_offset:security_buffer_offset+security_buffer_length]
        )

        # TODO: Use a map?

        if dialect_revision == Dialect.SMB_3_1_1:
            negotiate_context_offset: int = struct_unpack('<I', body_data[60:64])[0]
            return SMB311NegotiateResponse(
                **base_kwargs,
                negotiate_context_list=NegotiateContextList.from_bytes(
                    data=body_data[negotiate_context_offset - len(header):],
                    num_contexts=struct_unpack('<I', body_data[6:8])[0]
                )
            )
        elif dialect_revision is Dialect.SMB_2_0_2:
            return SMB202NegotiateResponse(**base_kwargs)
        elif dialect_revision is Dialect.SMB_2_1:
            return SMB210NegotiateResponse(**base_kwargs)
        elif dialect_revision is Dialect.SMB_3_0:
            return SMB300NegotiateResponse(**base_kwargs)
        elif dialect_revision is Dialect.SMB_3_0_2:
            return SMB302NegotiateResponse(**base_kwargs)
        elif dialect_revision is Dialect.SMB_2_WILDCARD:
            return SMB2WildcardNegotiateResponse(**base_kwargs)
        else:
            # TODO: Use proper exception.
            raise ValueError

    # TODO: Do. Also for SMB311.
    def __bytes__(self):
        ...

    # TODO: Do.
    def __len__(self):
        ...


@dataclass
class SMB300NegotiateResponse(NegotiateResponse):
    pass


@dataclass
class SMB302NegotiateResponse(NegotiateResponse):
    pass


@dataclass
class SMB311NegotiateResponse(NegotiateResponse):
    negotiate_context_list: NegotiateContextList


@dataclass
class SMB202NegotiateResponse(NegotiateResponse):
    pass


@dataclass
class SMB210NegotiateResponse(NegotiateResponse):
    pass


# TODO: Is this reasonable?
@dataclass
class SMB2WildcardNegotiateResponse(NegotiateResponse):
    pass


@dataclass
@Message.register
class NegotiateRequest(RequestMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 36
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_NEGOTIATE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedNegotiateRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = NegotiateResponse

    dialects: Tuple[Dialect, ...]
    security_mode: SecurityMode
    client_guid: UUID

    @property
    def dialect_count(self) -> int:
        return len(self.dialects)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> NegotiateRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        dialect_count: int = struct_unpack('<H', body_data[2:4])[0]
        if dialect_count <= 0:
            raise NoNegotiateDialectsError(observed_dialect_count=dialect_count)

        dialects: Tuple[Dialect, ...] = tuple(
            Dialect(dialect_value)
            for dialect_value in struct_unpack(f'<{dialect_count * "H"}', body_data[36:36 + dialect_count * 2])
        )
        body_base_kwargs = dict(
            security_mode=SecurityMode(struct_unpack('<H', body_data[4:6])[0]),
            # TODO: The bytes may need to be reorder.
            client_guid=UUID(bytes=body_data[12:28]),
            dialects=dialects
        )

        if any(dialect in dialects for dialect in [Dialect.SMB_3_1_1, Dialect.SMB_3_0_2, Dialect.SMB_3_0]):
            capabilities = CapabilitiesFlag.from_int(
                struct_unpack(f'<{dialect_count * "H"}', body_data[36:36 + dialect_count * 2])
            )

            if Dialect.SMB_3_1_1 in dialects:
                negotiate_context_offset = struct_unpack('<H', body_data[28:32])[0]
                negotiate_context_count = struct_unpack('<H', body_data[32:34])[0]

                return SMB311NegotiateRequest(
                    header=header,
                    **body_base_kwargs,
                    capabilities=capabilities,
                    negotiate_context_list=NegotiateContextList.from_bytes(
                        data=body_data[negotiate_context_offset - len(header):],
                        num_contexts=negotiate_context_count
                    )
                )
            elif Dialect.SMB_3_0_2 in dialects:
                return SMB302NegotiateRequest(
                    header=header,
                    **body_base_kwargs,
                    capabilities=capabilities
                )
            elif Dialect.SMB_3_0 in dialects:
                return SMB300NegotiateRequest(
                    header=header,
                    **body_base_kwargs,
                    capabilities=capabilities
                )
            else:
                raise NotImplementedNegotiateRequestError(
                    f'Expected `dialects` to include one of SMB_3_1_1, SMB_3_0_2, and SMB_3_0, observed {dialects}.'
                )
        elif any(dialect in dialects for dialect in [Dialect.SMB_2_1, Dialect.SMB_2_0_2]):
            capabilities_value = body_data[8:12]
            if capabilities_value != b'\x00\x00\x00\x00':
                raise NegotiateRequestCapabilitiesNotEmpty(observed_capabilities_value=capabilities_value)

            # TODO: Do something with this?
            client_start_time = body_data[28:36]

            if Dialect.SMB_2_1 in dialects:
                return SMB210NegotiateRequest(header=header, **body_base_kwargs)
            elif Dialect.SMB_2_0_2 in dialects:
                return SMB202NegotiateRequest(header=header, **body_base_kwargs)
            else:
                raise NotImplementedNegotiateRequestError(
                    f'Expected `dialects` to include one of SMB_2_1 and SMB_2_0_2, observed {dialects}.'
                )
        else:
            raise NotImplementedNegotiateRequestError(
                f'Expected `dialects` to include one of SMB_2_1 and SMB_2_0_2, observed {dialects}.'
            )

    def __bytes__(self) -> bytes:
        capabilities: Optional[CapabilitiesFlag] = (
            getattr(self, 'capabilities') if issubclass(type(self), SMB3XNegotiateRequest)
            else None
        )

        negotiate_context_list: Optional[NegotiateContextList] = (
            getattr(self, 'negotiate_context_list') if isinstance(self, SMB311NegotiateRequest)
            else None
        )

        dialects_bytes_data: bytes = struct_pack(f'<{len(self.dialects) * "H"}', *self.dialects)
        num_padding: int = (8 - (len(dialects_bytes_data) % 8)) % 8

        return bytes(self.header) + b''.join([
            struct_pack('<H', 36),
            struct_pack('<H', self.dialect_count),
            struct_pack('<H', self.security_mode),
            b'\x00\x00',
            struct_pack('<I', capabilities) if capabilities is not None else b'\x00\x00\x00\x00',
            self.client_guid.bytes,
            (
                struct_pack('<I', 64 + 36 + len(dialects_bytes_data) + num_padding)
                + struct_pack('<H', len(negotiate_context_list))
                + b'\x00\x00'
            ) if negotiate_context_list is not None else 8 * b'\x00',
            dialects_bytes_data,
            (num_padding * b'\x00' + bytes(negotiate_context_list)) if negotiate_context_list is not None else b''
        ])

    def __len__(self) -> int:
        dialects_bytes_data_len = 2 * len(self.dialects)
        num_padding: int = (8 - (dialects_bytes_data_len % 8)) % 8

        return len(self.header) + 36 + dialects_bytes_data_len + (
           (num_padding + len(getattr(self, 'negotiate_context_ist'))) if isinstance(self, SMB311NegotiateRequest) else 0
        )


@dataclass
class SMB2XNegotiateRequest(NegotiateRequest, ABC):
    pass


@dataclass
class SMB202NegotiateRequest(SMB2XNegotiateRequest):
    pass


@dataclass
class SMB210NegotiateRequest(SMB2XNegotiateRequest):
    pass


@dataclass
class SMB3XNegotiateRequest(NegotiateRequest, ABC):
    capabilities: CapabilitiesFlag


@dataclass
class SMB300NegotiateRequest(SMB3XNegotiateRequest):
    pass


@dataclass
class SMB302NegotiateRequest(SMB3XNegotiateRequest):
    pass


@dataclass
class SMB311NegotiateRequest(SMB3XNegotiateRequest):
    negotiate_context_list: NegotiateContextList