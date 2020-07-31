from enum import Enum, auto


class SessionState(Enum):
    IN_PROGRESS = auto()
    VALID = auto()
    EXPIRED = auto()
