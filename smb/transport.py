from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, error as struct_error, pack as struct_pack
from typing import Union, Optional, Final
from ipaddress import IPv4Address, IPv6Address
from asyncio import StreamWriter, StreamReader, open_connection as asyncio_open_connection, wait_for as asyncio_wait_for

from smb.message import SMBMessage


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


# TODO: Move somewhere -- but where?
@dataclass
class TCPIPTransport:
    address: Final[Union[str, IPv4Address, IPv6Address]]
    port_number: Final[int]
    timeout_in_seconds: Final[float] = 3.0
    read_size: int = 4096

    def __post_init__(self):
        self.reader: Optional[StreamReader] = None
        self.writer: Optional[StreamWriter] = None

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def __aenter__(self):
        self.reader, self.writer = await asyncio_wait_for(
            fut=asyncio_open_connection(host=self.address, port=self.port_number),
            timeout=self.timeout_in_seconds
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.writer.close()
        await self.writer.wait_closed()
