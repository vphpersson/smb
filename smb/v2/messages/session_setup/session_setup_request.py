from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from struct import unpack as struct_unpack, pack as struct_pack
from typing import Optional, ClassVar

from smb.v2.smbv2_header import SMBv2Header, SMB202SyncHeader, SMB210SyncHeader, SMB300SyncHeader, \
    SMB302SyncHeader, SMB311SyncHeader, SMBv2Command, SMBv2Flag
from smb.v2.smbv2_message import SMBv2Message
from smb.v2.dialect import Dialect
from smb.v2.security_mode import SecurityMode
from smb.v2.capabilities import CapabilitiesFlag
from smb.exceptions import MalformedSessionSetupRequestError, IncorrectStructureSizeError


class SessionSetupRequestFlag(IntEnum):
    _SMB2_SESSION_FLAG_NONE = 0x00
    SMB2_SESSION_FLAG_BINDING = 0x01


@dataclass
class SessionSetupRequest(SMBv2Message):
    flags: SessionSetupRequestFlag
    security_mode: SecurityMode
    capabilities: CapabilitiesFlag
    previous_session_id: bytes
    security_buffer: bytes

    structure_size: ClassVar[int] = 25
    _channel: ClassVar[bytes] = 4 * b'\x00'

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header):

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedSessionSetupRequestError(str(e)) from e

        if body_data[8:12] != cls._channel:
            # TODO: Use proper exception.
            raise ValueError

        security_buffer_offset: int = struct_unpack('<H', body_data[12:14])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[14:16])[0]

        return cls(
            header=header,
            flags=SessionSetupRequestFlag(struct_unpack('<B', body_data[2:3])[0]),
            security_mode=SecurityMode(struct_unpack('<B', body_data[3:4])[0]),
            capabilities=CapabilitiesFlag.from_mask(struct_unpack('<I', body_data[4:8])[0]),
            previous_session_id=body_data[16:24],
            security_buffer=data[security_buffer_offset:security_buffer_offset+security_buffer_length]
        )

    @classmethod
    def make_session_setup_request(
        cls,
        dialect: Dialect,
        # TODO: Support async headers...
        session_id: int,
        security_mode: SecurityMode,
        security_buffer: bytes,
        capabilities: Optional[CapabilitiesFlag] = None,
        session_flag_binding: bool = False,
        num_credits: int = 8192
    ) -> SessionSetupRequest:

        headers_base_kwargs = dict(
            command=SMBv2Command.SMB2_SESSION_SETUP,
            flags=SMBv2Flag(),
            session_id=session_id,
            num_credits=num_credits,
        )

        credit_charge = 1
        channel_sequence = b''

        if dialect == Dialect.SMB_2_0_2:
            header = SMB202SyncHeader(**headers_base_kwargs, status=None)
        elif dialect == Dialect.SMB_2_1:
            header = SMB210SyncHeader(**headers_base_kwargs, credit_charge=credit_charge, status=None)
        elif dialect == Dialect.SMB_3_0:
            header = SMB300SyncHeader(
                **headers_base_kwargs,
                credit_charge=credit_charge,
                channel_sequence=channel_sequence
            )
        elif dialect == Dialect.SMB_3_0_2:
            header = SMB302SyncHeader(
                **headers_base_kwargs,
                credit_charge=credit_charge,
                channel_sequence=channel_sequence
            )
        elif dialect == Dialect.SMB_3_1_1:
            header = SMB311SyncHeader(
                **headers_base_kwargs,
                credit_charge=credit_charge,
                channel_sequence=channel_sequence
            )
        else:
            # TODO Use proper exception.
            raise ValueError

        return cls(
            header=header,
            flags=SessionSetupRequestFlag(0x01 if session_flag_binding else 0x00),
            security_mode=security_mode,
            capabilities=capabilities if capabilities is not None else CapabilitiesFlag(dfs=True),
            previous_session_id=8 * b'\x00',
            security_buffer=security_buffer
        )

    def __len__(self) -> int:
        return len(self.header) + 24 + len(self.security_buffer)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', 25),
            struct_pack('<B', self.flags.value),
            struct_pack('<B', self.security_mode.value),
            struct_pack('<I', self.capabilities.to_mask()),
            self._channel,
            struct_pack('<H', len(self.header) + 24),
            struct_pack('<H', len(self.security_buffer)),
            self.previous_session_id,
            self.security_buffer
        ])
