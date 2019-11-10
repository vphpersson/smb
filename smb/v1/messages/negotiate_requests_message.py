from dataclasses import dataclass

from smb.v1.smb_data_block import SMBDataBlock
from smb.v1.smbv1_header import SMBv1Header
from smb.v1.smbv1_message import SMBv1Message
from smb.v1.smb_parameter_block import SMBParameterBlock


class MalformedBufferFormatError(Exception):
    def __init__(self, bytes_data: bytes):
        super().__init__('The buffer format is not 0x02.')
        self.bytes_data = bytes_data


@dataclass
class SMBNegotiateRequestDataBlock(SMBDataBlock):

    BUFFER_FORMAT = b'\x02'

    def dialects(self):

        buffer_format: bytes = self.bytes_data[0:1]

        if buffer_format != self.BUFFER_FORMAT:
            raise MalformedBufferFormatError(self.bytes_data)

        return tuple(
            dialect_str.rstrip(b'\x00').decode() for dialect_str in self.bytes_data[1:].split(buffer_format)
        )

    def __bytes__(self):
        return self.make_length_prefix(count=self.bytes_count) \
            + self.BUFFER_FORMAT + self.BUFFER_FORMAT.join(dialect.encode() + b'\x00' for dialect in self.dialects())


@dataclass
class SMBNegotiateRequestMessage(SMBv1Message):

    data_block: SMBNegotiateRequestDataBlock

    def __init__(self, header: SMBv1Header, body_bytes: bytes):

        parameter_block = SMBParameterBlock.from_bytes(data=body_bytes)
        data_block = SMBNegotiateRequestDataBlock.from_bytes(data=body_bytes[len(parameter_block):])

        super().__init__(header=header, parameter_block=parameter_block, data_block=data_block)

    def dialects(self):
        return self.data_block.dialects()
