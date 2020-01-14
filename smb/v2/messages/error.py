from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack

from smb.v2.messages import ResponseMessage
from smb.v2.header import Header, SMB311SyncResponseHeader


@dataclass
class ErrorResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 9
    _RESERVED: ClassVar[bytes] = bytes(1)

    # TODO: Temporary variables while not supporting 3.1.1.
    _error_context_count: ClassVar[int] = 0
    _byte_count: ClassVar[int] = 0
    _error_data: ClassVar[bytes] = b''

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> ErrorResponse:
        if isinstance(header, SMB311SyncResponseHeader):
            raise NotImplementedError

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self._error_context_count),
            self._RESERVED,
            struct_pack('<I', self._byte_count),
            self._error_data
        ])

    def __len__(self) -> int:
        # TODO: When supporting 3.1.1, also count size of `ErrorData`.
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self._error_data)
