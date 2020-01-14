from enum import IntEnum


# TODO: Rather than being an `IntEnum`, shouldn't this be a flag, to indicate that it can be empty?
class SessionSetupRequestFlag(IntEnum):
    # NOTE: Not part of the flag according to the spec.
    SMB2_SESSION_FLAG_NONE = 0x00
    SMB2_SESSION_FLAG_BINDING = 0x01
