from __future__ import annotations
from dataclasses import dataclass


@dataclass
class FileId:
    persistent_file_handle: bytes
    volatile_file_handle: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> FileId:
        return cls(
            persistent_file_handle=data[:8],
            volatile_file_handle=data[8:16]
        )

    def __bytes__(self) -> bytes:
        return self.persistent_file_handle + self.volatile_file_handle

    def __len__(self) -> int:
        return 16
