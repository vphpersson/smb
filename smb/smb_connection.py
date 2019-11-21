from dataclasses import dataclass
from typing import Union, Optional
from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from asyncio import StreamReader, StreamWriter, wait_for as asyncio_wait_for, \
    open_connection as asyncio_open_connection,  Queue as AsyncioQueue, Event as AsyncioEvent, \
    CancelledError, create_task as asyncio_create_task, Task

from smb.smb_message import SMBMessage
from smb.transport import Transport, NotEnoughDataError


@dataclass
class NegotiatedDetails(ABC):
    pass


class SMBConnection(ABC):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a1df6781-a507-48a7-bcdb-be9ef0c09c97
    """

    def __init__(
        self,
        host_address: Union[str, IPv4Address, IPv6Address],
        port_number: int = 445,
        timeout_in_seconds: float = 3.0
    ):
        """
        :param host_address: The address of the host to connect to.
        :param port_number: The port number that the remote SMB service uses.
        :param timeout_in_seconds: The number of seconds to wait for a connection before timing out.
        """

        # Parameters needed for connecting to the remote host.
        self._host_address: Optional[Union[str, IPv4Address, IPv6Address]] = host_address
        self._port_number: int = port_number
        self._timeout_in_seconds: float = timeout_in_seconds

        # Objects for reading and writing data to the remote host when the connection has been established.
        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None
        self._incoming_task: Optional[Task] = None
        self._outgoing_task: Optional[Task] = None

        # Data structures for handling incoming and outgoing messages.
        self._incoming_smb_messages_queue = AsyncioQueue()
        self._outgoing_smb_messages_queue = AsyncioQueue()

        # TODO: Implement?
        # Event for handling user-initiated, controlled disconnect.
        self._disconnect_event = AsyncioEvent()

    @abstractmethod
    def _transport_from_bytes(self, data: bytes) -> Transport:
        pass

    @abstractmethod
    async def negotiate(self):
        pass

    @abstractmethod
    async def _receive_message(self):
        pass

    async def _handle_incoming_bytes(self):

        # TODO: Maybe there is a better way to use a buffer.
        # TODO: The `read` sizes are arbitrary. What is optimal?
        buffer = b''
        while not self._disconnect_event.is_set():
            try:
                if len(buffer) < 4:
                    buffer += await self._reader.read(4096)
                    continue

                try:
                    transport = self._transport_from_bytes(data=buffer)
                except NotEnoughDataError:
                    buffer += await self._reader.read(4096)
                    continue

                await self._incoming_smb_messages_queue.put(transport.smb_message)
                buffer = buffer[len(transport):]
            except CancelledError:
                return

    async def _handle_outgoing_bytes(self):
        while not self._disconnect_event.is_set():
            smb_message: SMBMessage = await self._outgoing_smb_messages_queue.get()
            self._writer.write(
                data=bytes(
                    Transport(
                        stream_protocol_length=len(smb_message),
                        smb_message=smb_message
                    )
                )
            )
            await self._writer.drain()

    async def __aenter__(self):
        """Establish a connection to a remote SMB server."""

        self._reader, self._writer = await asyncio_wait_for(
            fut=asyncio_open_connection(host=self._host_address, port=self._port_number),
            timeout=self._timeout_in_seconds
        )

        self._incoming_task = asyncio_create_task(coro=self._handle_incoming_bytes())
        self._outgoing_task = asyncio_create_task(coro=self._handle_outgoing_bytes())

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._incoming_task.cancel()
        self._outgoing_task.cancel()
        self._writer.close()
        await self._writer.wait_closed()

