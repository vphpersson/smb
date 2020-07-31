from dataclasses import dataclass


@dataclass
class SequenceWindow:
    lower: int = 0
    upper: int = 1
