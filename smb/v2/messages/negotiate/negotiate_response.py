from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack
from abc import ABC
from uuid import UUID
from datetime import datetime
from typing import ClassVar

from msdsalgs.time import filetime_to_datetime

from smb.v2.smbv2_message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.v2.security_mode import SecurityMode
from smb.v2.dialect import Dialect
from smb.v2.capabilities import CapabilitiesFlag
from smb.v2.negotiate_context import NegotiateContextList
from smb.exceptions import IncorrectStructureSizeError, MalformedNegotiateResponseError


@dataclass
@register_smbv2_message
class NegotiateResponse(SMBv2ResponseMessage, ABC):
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

    structure_size: ClassVar[int] = 65
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_NEGOTIATE

    @property
    def system_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._system_time)

    @property
    def server_start_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._server_start_time)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> NegotiateResponse:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedNegotiateResponseError(str(e)) from e

        dialect_revision = Dialect(struct_unpack('<H', body_data[4:6])[0])
        security_buffer_offset: int = struct_unpack('<H', body_data[56:58])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[58:60])[0]

        base_kwargs = dict(
            header=header,
            dialect_revision=dialect_revision,
            security_mode=SecurityMode(struct_unpack('<H', body_data[2:4])[0]),
            server_guid=UUID(bytes=body_data[8:24]),
            capabilities=CapabilitiesFlag.from_mask(struct_unpack('<I', body_data[24:28])[0]),
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
