from dataclasses import dataclass
from typing import Union, Optional
from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from asyncio import StreamReader, StreamWriter, wait_for as asyncio_wait_for, \
    open_connection as asyncio_open_connection,  Queue as AsyncioQueue, Event as AsyncioEvent, \
    CancelledError, create_task as asyncio_create_task

from smb.smb_message import SMBMessage
from smb.transport import Transport, NotEnoughDataError


@dataclass
class NegotiatedDetails(ABC):
    pass


class SMBConnection(ABC):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a1df6781-a507-48a7-bcdb-be9ef0c09c97
    """

    def __init__(self):
        self._disconnect_event = AsyncioEvent()
        self._incoming_smb_messages_queue = AsyncioQueue()
        self._outgoing_smb_messages_queue = AsyncioQueue()

        self._remote_host_address: Optional[Union[str, IPv4Address, IPv6Address]] = None

    @abstractmethod
    def _transport_from_bytes(self, data: bytes) -> Transport:
        pass

    @abstractmethod
    async def negotiate(self):
        pass

    @abstractmethod
    async def _receive_message(self):
        pass

    async def _handle_incoming_bytes(self, reader: StreamReader, incoming_smb_messages_queue: AsyncioQueue):

        # TODO: Maybe there is a better way to use a buffer.
        # TODO: The `read` sizes are arbitrary. What is optimal?
        buffer = b''
        while not self._disconnect_event.is_set():
            try:
                if len(buffer) < 4:
                    buffer += await reader.read(4096)
                    continue

                try:
                    transport = self._transport_from_bytes(data=buffer)
                except NotEnoughDataError:
                    buffer += await reader.read(4096)
                    continue

                await incoming_smb_messages_queue.put(transport.smb_message)
                buffer = buffer[len(transport):]
            except CancelledError:
                return

    async def _handle_outgoing_bytes(self, writer: StreamWriter, outgoing_smb_messages_queue: AsyncioQueue):
        while not self._disconnect_event.is_set():
            smb_message: SMBMessage = await outgoing_smb_messages_queue.get()
            writer.write(
                data=bytes(
                    Transport(
                        stream_protocol_length=len(smb_message),
                        smb_message=smb_message
                    )
                )
            )
            await writer.drain()

    # TODO: Make into a context manager, so `reader` and `writer` can be closed.
    async def connect(
        self,
        host_address: Union[str, IPv4Address, IPv6Address],
        port_number: int = 445,
        timeout_in_seconds: float = 3.0
    ):
        """
        Establish a connection to a remote SMB server.

        :param host_address: The address of the host to connect to.
        :param port_number: The port number that the remote SMB service uses.
        :param timeout_in_seconds: The number of seconds to wait for a connection before timing out.
        :return:
        """

        reader, writer = await asyncio_wait_for(
            fut=asyncio_open_connection(host=host_address, port=port_number),
            timeout=timeout_in_seconds
        )

        self._remote_host_address = host_address

        # TODO: What to do with these tasks?

        incoming_task = asyncio_create_task(
            coro=self._handle_incoming_bytes(
                reader=reader,
                incoming_smb_messages_queue=self._incoming_smb_messages_queue,
            )
        )

        outgoing_task = asyncio_create_task(
            coro=self._handle_outgoing_bytes(
                writer=writer,
                outgoing_smb_messages_queue=self._outgoing_smb_messages_queue,
            )
        )
