from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack


@dataclass
class SMBDataBlock:
    bytes_data: bytes

    @property
    def bytes_count(self) -> int:
        return len(self.bytes_data)

    def __len__(self) -> int:
        return 2 + self.bytes_count

    @classmethod
    def from_bytes(cls, data: bytes) -> SMBDataBlock:
        bytes_count = struct_unpack('<H', data[0:2])[0]
        return cls(bytes_data=data[2:2+bytes_count])

    @staticmethod
    def make_length_prefix(count: int) -> bytes:
        return struct_pack('<H', count)

    def __bytes__(self) -> bytes:
        return self.make_length_prefix(count=self.bytes_count) + self.bytes_data
