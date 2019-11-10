from __future__ import annotations
from dataclasses import dataclass
from struct import pack as struct_pack

from smb.smb_message import SMBMessage
from smb.v1.smbv1_header import SMBv1Header, SMBv1Command
from smb.v1.smb_parameter_block import SMBParameterBlock
from smb.v1.smb_data_block import SMBDataBlock


@dataclass
class SMBv1Message(SMBMessage):
    header: SMBv1Header
    parameter_block: SMBParameterBlock
    data_block: SMBDataBlock

    def __len__(self) -> int:
        return len(self.header) + len(self.parameter_block) + len(self.data_block)

    def _pack_length_prefix(self) -> bytes:
        return struct_pack('>I', self.__len__())

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv1Header):

        from smb.v1.messages.negotiate_requests_message import SMBNegotiateRequestMessage

        body_bytes = data[len(header):]

        if header.command == SMBv1Command.SMB_COM_NEGOTIATE:
            return SMBNegotiateRequestMessage(header=header, body_bytes=body_bytes)
        else:
            parameter_block = SMBParameterBlock.from_bytes(data=data[32:])
            return cls(
                header=header,
                parameter_block=parameter_block,
                data_block=SMBDataBlock.from_bytes(data[len(header)+len(parameter_block):])
            )

    @classmethod
    def from_bytes(cls, data: bytes) -> SMBv1Message:
        smb_message: SMBMessage = super().from_bytes(data=data)
        if not isinstance(smb_message, SMBv1Message):
            # TODO: Use proper exception.
            raise ValueError
        return smb_message

    def __bytes__(self) -> bytes:
        return b''.join((
            self._pack_length_prefix(),
            bytes(self.header),
            bytes(self.parameter_block),
            bytes(self.data_block)
        ))
