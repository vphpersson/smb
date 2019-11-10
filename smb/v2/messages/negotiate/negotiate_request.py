from __future__ import annotations
from dataclasses import dataclass
from uuid import UUID
from typing import Tuple, Iterable, Optional, ClassVar
from abc import ABC
from struct import unpack as struct_unpack, pack as struct_pack
from secrets import token_bytes as secrets_token_bytes

from smb.v2.smbv2_header import SMBv2Header, SMB202SyncHeader, SMB210SyncHeader, SMB300SyncHeader, \
    SMB302SyncHeader, SMB311SyncHeader, SMBv2Command, SMBv2Flag
from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.dialect import Dialect
from smb.v2.security_mode import SecurityMode
from smb.v2.capabilities import CapabilitiesFlag
from smb.v2.negotiate_context import NegotiateContextList, PreauthIntegrityCapabilitiesContext, HashAlgorithm, \
    EncryptionCapabilitiesContext, Cipher, CompressionCapabilitiesContext, CompressionAlgorithm, \
    NetnameNegotiateContextIdContext
from smb.exceptions import IncorrectStructureSizeError, MalformedNegotiateRequestError,\
    NoNegotiateDialectsError, NegotiateRequestCapabilitiesNotEmpty, NotImplementedNegotiateRequestError
from smb.smb_message import SMBRequestMessage


# TODO: Is this missing `structure_size`?
@dataclass
@register_smbv2_message
class NegotiateRequest(SMBv2Message, SMBRequestMessage, ABC):

    dialects: Tuple[Dialect, ...]
    security_mode: SecurityMode
    client_guid: UUID
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_NEGOTIATE

    @property
    def dialect_count(self) -> int:
        return len(self.dialects)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> NegotiateRequest:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedNegotiateRequestError(str(e)) from e

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
            capabilities = CapabilitiesFlag.from_mask(
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

    @classmethod
    def make_negotiate_request(
        cls,
        dialects: Iterable[Dialect],
        client_guid: UUID,
        security_mode: SecurityMode,
        supported_ciphers: Optional[Iterable[Cipher]] = None,
        supported_compression_algorithms: Optional[Iterable[CompressionAlgorithm]] = None,
        net_name: Optional[str] = None,
        capabilities: Optional[CapabilitiesFlag] = None,
        salt: Optional[bytes] = None
    ):
        """
        Make an SMBv2 Negotiate request message.

        :param dialects: The supported dialects.
        :param client_guid: The GUID of the SMB client.
        :param security_mode:
        :param supported_ciphers:
        :param supported_compression_algorithms:
        :param net_name:
        :param capabilities:
        :param salt:
        :return: An SMBv2 Negotiate request message.
        """

        dialects = tuple(dialects)
        capabilities: CapabilitiesFlag = capabilities if capabilities is not None else CapabilitiesFlag()

        header_base_kwargs = dict(
            command=SMBv2Command.SMB2_NEGOTIATE,
            flags=SMBv2Flag(),
            message_id=None,
            session_id=0,
            num_credits=31,
            next_command_offset=0,
            tree_id=0,
            signature=16 * b'\x00'
        )

        message_base_kwargs = dict(
            dialects=dialects,
            security_mode=security_mode,
            client_guid=client_guid
        )

        credit_charge = 1
        # TODO: Not sure about this value.
        channel_sequence = b''

        if Dialect.SMB_3_1_1 in dialects:
            negotiate_context_list = NegotiateContextList((
                PreauthIntegrityCapabilitiesContext(
                    hash_algorithms=(HashAlgorithm.SHA_512,),
                    salt=salt if salt is not None else secrets_token_bytes(nbytes=32)
                )
            ))

            if supported_ciphers:
                negotiate_context_list.append(EncryptionCapabilitiesContext(ciphers=tuple(supported_ciphers)))

            if supported_compression_algorithms:
                negotiate_context_list.append(
                    CompressionCapabilitiesContext(
                        compression_algorithms=tuple(supported_compression_algorithms)
                    )
                )

            if net_name:
                negotiate_context_list.append(NetnameNegotiateContextIdContext(netname=net_name))

            return SMB311NegotiateRequest(
                header=SMB311SyncHeader(
                    **header_base_kwargs,
                    credit_charge=credit_charge,
                    channel_sequence=channel_sequence
                ),
                **message_base_kwargs,
                negotiate_context_list=negotiate_context_list,
                capabilities=capabilities
            )
        elif Dialect.SMB_3_0_2 in dialects:
            return SMB302NegotiateRequest(
                header=SMB302SyncHeader(
                    **header_base_kwargs,
                    credit_charge=credit_charge,
                    channel_sequence=channel_sequence
                ),
                **message_base_kwargs,
                capabilities=capabilities
            )
        elif Dialect.SMB_3_0 in dialects:
            return SMB300NegotiateRequest(
                header=SMB300SyncHeader(
                    **header_base_kwargs,
                    credit_charge=credit_charge,
                    channel_sequence=channel_sequence
                ),
                **message_base_kwargs,
                capabilities=capabilities
            )
        elif Dialect.SMB_2_1 in dialects:
            return SMB210NegotiateRequest(
                header=SMB210SyncHeader(
                    **header_base_kwargs,
                    credit_charge=credit_charge,
                    status=None
                ),
                **message_base_kwargs
            )
        elif Dialect.SMB_2_0_2 in dialects:
            return SMB202NegotiateRequest(
                header=SMB202SyncHeader(
                    **header_base_kwargs,
                    status=None
                ),
                **message_base_kwargs
            )
        else:
            # TODO: Use proper exception.
            raise ValueError

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
