from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import Tuple, Union


@dataclass
class SMBParameterBlock:
    _data: bytes

    @property
    def word_count(self) -> int:
        return struct_unpack('<B', self._data[0:1])[0]

    def words(self) -> Tuple[Union[int, bytes]]:
        return tuple(self._data[1+2*i:1+2*i+2] for i in range(self.word_count))

    def __len__(self) -> int:
        return 1 + 2 * self.word_count

    @classmethod
    def from_bytes(cls, data: bytes) -> SMBParameterBlock:
        # TODO: The `data` contains both parameter block data and data block data.
        return cls(_data=data)

    @staticmethod
    def make_length_prefix(count: int) -> bytes:
        return struct_pack('<B', count)

    def __bytes__(self) -> bytes:
        return self.make_length_prefix(count=self.word_count) + b''.join(
            struct_pack('<H', word)
            for word in self.words()
        )
