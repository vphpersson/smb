from dataclasses import dataclass
from uuid import UUID
from abc import ABC
from typing import Optional, Set

from smb.connection import NegotiatedDetails
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.negotiate_context import HashAlgorithm, Cipher, CompressionAlgorithm


@dataclass
class SMBv2NegotiatedDetails(NegotiatedDetails, ABC):
    dialect: Dialect
    require_signing: bool
    server_guid: UUID
    max_transact_size: int
    max_read_size: int
    max_write_size: int


@dataclass
class SMB2XNegotiatedDetails(SMBv2NegotiatedDetails):
    pass


@dataclass
class SMB202NegotiatedDetails(SMB2XNegotiatedDetails):
    pass


@dataclass
class SMB210NegotiatedDetails(SMB2XNegotiatedDetails):
    supports_file_leasing: bool
    supports_multi_credit: bool


@dataclass
class SMB3XNegotiatedDetails(SMBv2NegotiatedDetails, ABC):
    supports_file_leasing: bool
    supports_multi_credit: bool
    supports_directory_leasing: bool
    supports_multi_channel: bool
    supports_persistent_handles: bool
    supports_encryption: bool
    # client_capabilities: CapabilitiesFlag
    # server_capabilities: CapabilitiesFlag
    # client_security_mode: SecurityMode
    # server_security_mode: SecurityMode


@dataclass
class SMB300NegotiatedDetails(SMB3XNegotiatedDetails):
    pass


@dataclass
class SMB302NegotiatedDetails(SMB3XNegotiatedDetails):
    pass


@dataclass
class SMB311NegotiateDetails(SMB3XNegotiatedDetails):
    preauth_integrity_hash_id: Optional[HashAlgorithm] = None
    preauth_integrity_hash_value: Optional[bytes] = None
    cipher_id: Optional[Cipher] = None
    compression_ids: Optional[Set[CompressionAlgorithm]] = None
