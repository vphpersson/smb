from __future__ import annotations
from enum import IntEnum
from typing import List, Tuple
from struct import unpack as struct_unpack, pack as struct_pack
from dataclasses import dataclass
from abc import ABC, abstractmethod


class ContextType(IntEnum):
    SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
    SMB2_ENCRYPTION_CAPABILITIES = 0x0002
    SMB2_COMPRESSION_CAPABILITIES = 0x0003
    SMB2_NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005


class HashAlgorithm(IntEnum):
    SHA_512 = 0x0001


class Cipher(IntEnum):
    AES_128_CCM = 0x0001
    AES_128_GCM = 0x0002


class CompressionAlgorithm(IntEnum):
    NONE = 0x0000
    LZNT1 = 0x0001
    LZ77 = 0x0002
    LZ77_HUFFMAN = 0x0003


@dataclass
class NegotiateContext(ABC):

    @classmethod
    def from_bytes(cls, data: bytes) -> NegotiateContext:
        context_type = ContextType(struct_unpack('<H', data[:2])[0])
        data_length: int = struct_unpack('<H', data[2:4])[0]

        context_data: bytes = data[8:8+data_length]

        if context_type == ContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
            if cls != PreauthIntegrityCapabilitiesContext:
                # TODO: Use proper exception.
                raise ValueError
            return PreauthIntegrityCapabilitiesContext.from_context_data_bytes(context_data=context_data)
        elif context_type == ContextType.SMB2_ENCRYPTION_CAPABILITIES:
            if cls != EncryptionCapabilitiesContext:
                # TODO: Use proper exception.
                raise ValueError
            return EncryptionCapabilitiesContext.from_context_data_bytes(context_data=context_data)
        elif context_type == ContextType.SMB2_COMPRESSION_CAPABILITIES:
            if cls != CompressionCapabilitiesContext:
                # TODO: Use proper exception.
                raise ValueError
            return CompressionCapabilitiesContext.from_context_data_bytes(context_data=context_data)
        elif context_type == ContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
            if cls != NetnameNegotiateContextIdContext:
                # TODO: Use proper exception.
                raise ValueError
            return NetnameNegotiateContextIdContext.from_context_data_bytes(context_data=context_data)
        else:
            # TODO: Use proper exception.
            raise ValueError

    def __len__(self) -> int:
        return len(self.__bytes__())

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass


class NegotiateContextList(list):

    def __init__(self, iterable=()):
        super().__init__(iterable)

    @classmethod
    def from_bytes(cls, data: bytes, num_contexts: int) -> NegotiateContextList:

        negotiate_context_list: List[NegotiateContext] = list()
        offset = 0
        for i in range(num_contexts):
            negotiate_context = NegotiateContext.from_bytes(data=data[offset:])

            negotiate_context_len = len(negotiate_context)
            # Calculate offset of next context. Pad to nearest 8 bytes.
            offset += negotiate_context_len + 8 - (negotiate_context_len % 8)

            negotiate_context_list.append(negotiate_context)

        return cls(negotiate_context_list)

    # TODO: `len` is problematic... Use `bytes_len`?

    def __bytes__(self) -> bytes:
        bytes_data = b''
        offset = 0
        for negotiate_context in self.__iter__():
            this_offset: int = offset
            negotiate_context_bytes = bytes(negotiate_context)

            offset += len(negotiate_context_bytes) + 8 - (len(negotiate_context_bytes) % 8)

            bytes_data += negotiate_context_bytes + (offset - this_offset - len(negotiate_context_bytes)) * b'\00'

        return bytes_data


@dataclass
class PreauthIntegrityCapabilitiesContext(NegotiateContext):
    hash_algorithms: Tuple[HashAlgorithm, ...]
    salt: bytes

    @classmethod
    def from_context_data_bytes(cls, context_data: bytes) -> PreauthIntegrityCapabilitiesContext:
        hash_algorithm_count: int = struct_unpack('<H', context_data[:2])[0]
        if hash_algorithm_count < 1:
            # TODO: Use proper exception.
            raise ValueError

        salt_length: int = struct_unpack('<H', context_data[2:4])[0]

        return cls(
            hash_algorithms=tuple(
                HashAlgorithm(hash_algorithm_value)
                for hash_algorithm_value in struct_unpack(
                    f'<{hash_algorithm_count * "H"}', context_data[4:4+hash_algorithm_count*2]
                )
            ),
            salt=context_data[4+hash_algorithm_count*2:4+hash_algorithm_count*2+salt_length]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PreauthIntegrityCapabilitiesContext:
        negotiate_context: NegotiateContext = super().from_bytes(data)
        if not isinstance(negotiate_context, PreauthIntegrityCapabilitiesContext):
            # TODO: Use proper exception.
            raise ValueError
        return negotiate_context

    def __bytes__(self) -> bytes:
        data: bytes = b''.join([
            struct_pack('<H', len(self.hash_algorithms)),
            struct_pack(f'<{len(self.hash_algorithms) * "H"}', *self.hash_algorithms),
            self.salt
        ])

        return b''.join([
            struct_pack('<H', ContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES),
            struct_pack('<H', len(data)),
            b'\x00\x00\x00\x00',
            data
        ])


@dataclass
class EncryptionCapabilitiesContext(NegotiateContext):
    ciphers: Tuple[Cipher, ...]

    @classmethod
    def from_context_data_bytes(cls, context_data: bytes) -> EncryptionCapabilitiesContext:
        ciphers_count: int = struct_unpack('<H', context_data[:2])[0]
        if ciphers_count < 1:
            # TODO: Use proper exception.
            raise ValueError
        return cls(
            ciphers=tuple(
                Cipher(cipher_value)
                for cipher_value in struct_unpack(f'<{ciphers_count * "H"}', context_data[2:2+ciphers_count*2])
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptionCapabilitiesContext:
        negotiate_context: NegotiateContext = super().from_bytes(data)
        if not isinstance(negotiate_context, EncryptionCapabilitiesContext):
            # TODO: Use proper exception.
            raise ValueError
        return negotiate_context

    def __bytes__(self) -> bytes:
        data: bytes = b''.join([
            struct_pack('<H', len(self.ciphers)),
            struct_pack(f'<{len(self.ciphers) * "H"}', *self.ciphers)
        ])

        return b''.join([
            struct_pack('<H', ContextType.SMB2_ENCRYPTION_CAPABILITIES),
            struct_pack('<H', len(data)),
            b'\x00\x00\x00\x00',
            data
        ])


@dataclass
class CompressionCapabilitiesContext(NegotiateContext):
    compression_algorithms: Tuple[CompressionAlgorithm, ...]

    @classmethod
    def from_context_data_bytes(cls, context_data: bytes) -> CompressionCapabilitiesContext:
        count: int = struct_unpack('<H', context_data[:2])[0]
        # TODO: No requirement about `>0` in spec...
        return cls(
            compression_algorithms=tuple(
                CompressionAlgorithm(value)
                for value in struct_unpack(f'<{count * "H"}', context_data[8:8+count*2])
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CompressionCapabilitiesContext:
        negotiate_context: NegotiateContext = super().from_bytes(data)
        if not isinstance(negotiate_context, CompressionCapabilitiesContext):
            # TODO: use proper exception.
            raise ValueError
        return negotiate_context

    def __bytes__(self) -> bytes:
        data: bytes = b''.join([
            struct_pack('<H', len(self.compression_algorithms)),
            struct_pack(f'<{len(self.compression_algorithms) * "H"}', *self.compression_algorithms)
        ])

        return b''.join([
            struct_pack('<H', ContextType.SMB2_COMPRESSION_CAPABILITIES),
            struct_pack('<H', len(data)),
            b'\x00\x00\x00\x00',
            data
        ])


@dataclass
class NetnameNegotiateContextIdContext(NegotiateContext):
    netname: str

    @classmethod
    def from_context_data_bytes(cls, context_data: bytes) -> NetnameNegotiateContextIdContext:
        # TODO: Do I need to strip the trailing null byte?
        #   "A null-terminated Unicode string containing the server name and specified by the client application."
        return cls(
            netname=context_data[:-1].decode('utf-16-le')
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> NetnameNegotiateContextIdContext:
        negotiate_context: NegotiateContext = super().from_bytes(data)
        if not isinstance(negotiate_context, NetnameNegotiateContextIdContext):
            # TODO: Use proper exception.
            raise ValueError
        return negotiate_context

    def __bytes__(self) -> bytes:
        data: bytes = self.netname.encode('utf-16-le') + b'\x00'
        return b''.join([
            struct_pack('<H', ContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID),
            struct_pack('<H', len(data)),
            b'\x00\x00\x00\x00',
            data
        ])
