from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, error as struct_error, pack as struct_pack

from smb.smb_message import SMBMessage


class NotEnoughDataError(Exception):
    pass


@dataclass
class Transport:
    stream_protocol_length: int
    smb_message: SMBMessage

    @classmethod
    def from_bytes(cls, data: bytes, **smb_message_options) -> Transport:

        # TODO: The first byte  is supposed to be `b'\x00'`. Check.

        try:
            stream_protocol_length: int = struct_unpack('>I', b'\x00' + data[1:4])[0]
        except struct_error as e:
            raise NotEnoughDataError from e

        if len(data) < (stream_protocol_length + 4):
            raise NotEnoughDataError

        message_data = data[4:4+stream_protocol_length]

        return cls(
            stream_protocol_length=stream_protocol_length,
            smb_message=SMBMessage.from_bytes(data=message_data, **smb_message_options)
        )

    def __len__(self) -> int:
        return 4 + self.stream_protocol_length

    def __bytes__(self) -> bytes:
        return struct_pack('>I', self.stream_protocol_length) + bytes(self.smb_message)
