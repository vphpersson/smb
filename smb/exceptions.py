from typing import Any


class NotImplementedSMBMessageError(NotImplementedError):
    pass


class NotImplementedSMBv2MessageError(NotImplementedSMBMessageError):
    pass


class NotImplementedNegotiateRequestError(NotImplementedSMBv2MessageError):
    pass


class MalformedSMBMessageError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)


class MalformedSMBv2MessageError(MalformedSMBMessageError):
    pass


class IncorrectStructureSizeError(MalformedSMBMessageError):
    def __init__(self, observed_structure_size: Any, expected_structure_size: int):
        super().__init__(f'Expected structure size {expected_structure_size}, observed {observed_structure_size}.')
        self.observed_STRUCTURE_SIZE: Any = observed_structure_size
        self.expected_STRUCTURE_SIZE: int = expected_structure_size


class MalformedNegotiateRequestError(MalformedSMBv2MessageError):
    pass


class NoNegotiateDialectsError(MalformedNegotiateRequestError):
    def __init__(self, observed_dialect_count: Any):
        super().__init__(f'The number of dialects specified is {observed_dialect_count}. Should be a positive integer.')
        self.observed_dialect_count = observed_dialect_count


class NegotiateRequestCapabilitiesNotEmpty(MalformedNegotiateRequestError):
    def __init__(self, observed_capabilities_value: bytes):
        super().__init__(f'Expected empty capabilities, observed {observed_capabilities_value}.')
        self.observed_capabilities_value = observed_capabilities_value


class MalformedNegotiateResponseError(MalformedSMBv2MessageError):
    pass


class MalformedSessionSetupRequestError(MalformedSMBv2MessageError):
    pass


class MalformedLogoffRequestError(MalformedSMBv2MessageError):
    pass


class MalformedLogoffResponseError(MalformedSMBv2MessageError):
    pass


class MalformedCreateRequestError(MalformedSMBv2MessageError):
    pass


# TODO: Have these "NonEmpty" error belong to a specific class?

class NonEmptySecurityFlagsError(MalformedCreateRequestError):
    def __init__(self, observed_security_flags_value: int):
        super().__init__(f'Expected empty `SecurityFlags` value, got {observed_security_flags_value}.')
        self.observed_security_flags_value: int = observed_security_flags_value


class NonEmptySmbCreateFlagsError(MalformedCreateRequestError):
    def __init__(self, observed_smb_create_flags_value: bytes):
        super().__init__(f'Expected empty `SmbCreateFlags` value, got {observed_smb_create_flags_value}.')
        self.observed_smb_create_flags_value: bytes = observed_smb_create_flags_value


class NonEmptyCreateReservedError(MalformedCreateRequestError):
    def __init__(self, observed_reserved_value: bytes):
        super().__init__(f'Expected empty `Reserved` value, got {observed_reserved_value}.')
        self.observed_reserved_value: bytes = observed_reserved_value


class InvalidCreateOplockLevelValueError(MalformedCreateRequestError):
    pass


class InvalidCreateImpersonationLevelValueError(MalformedCreateRequestError):
    pass


class InvalidCreateDesiredAccessValueError(MalformedCreateRequestError):
    pass


class InvalidCreateFileAttributesValueError(MalformedCreateRequestError):
    pass


class InvalidCreateShareAccessValueError(MalformedCreateRequestError):
    pass


class InvalidCreateDispositionValueError(MalformedCreateRequestError):
    pass


class InvalidCreateOptionsValueError(MalformedCreateRequestError):
    pass


class InvalidCreateNameError(MalformedCreateRequestError):
    pass


class MalformedCreateResponseError(MalformedSMBv2MessageError):
    pass


class InvalidCreateResponseOplockLevelError(MalformedCreateResponseError):
    pass


class InvalidCreateResponseFlagError(MalformedCreateResponseError):
    pass


class InvalidCreateResponseActionError(MalformedCreateResponseError):
    pass


class InvalidCreateResponseFileAttributesError(MalformedCreateResponseError):
    pass


class MalformedReadRequestError(MalformedSMBv2MessageError):
    pass


class InvalidReadRequestFlagError(MalformedReadRequestError):
    pass


class InvalidReadRequestChannelError(MalformedReadRequestError):
    pass


class InvalidReadRequestReadChannelInfoOffsetError(MalformedReadRequestError):
    pass


class InvalidReadRequestReadChannelLengthError(MalformedReadRequestError):
    pass


class MalformedReadResponseError(MalformedSMBv2MessageError):
    pass


class NonEmptyReadResponseReservedValueError(MalformedReadResponseError):
    def __init__(self, observed_reserved_value: bytes):
        super().__init__(f'Expected empty `Reserved` value, got {observed_reserved_value}.')
        self.observed_reserved_value: bytes = observed_reserved_value


class NonEmptyReadResponseReserved2ValueError(MalformedReadResponseError):
    def __init__(self, observed_reserved_2_value: bytes):
        super().__init__(f'Expected empty `Reserved2` value, got {observed_reserved_2_value}.')
        self.observed_reserved_2_value: bytes = observed_reserved_2_value


class MalformedCloseRequestError(MalformedSMBv2MessageError):
    pass


class NonEmptyCloseRequestReservedValueError(MalformedCloseRequestError):
    def __init__(self, observed_reserved_value: bytes):
        super().__init__(f'Expected empty `Reserved` value, got {observed_reserved_value}.')
        self.observed_reserved_value: bytes = observed_reserved_value


class InvalidCloseRequestFlagValueError(MalformedCloseRequestError):
    pass


class MalformedCloseResponseError(MalformedSMBv2MessageError):
    pass


class InvalidCloseResponseFlagValueError(MalformedCloseRequestError):
    pass


class NonEmptyCloseResponseReservedValueError(MalformedCloseResponseError):
    def __init__(self, observed_reserved_value: bytes):
        super().__init__(f'Expected empty `Reserved` value, got {observed_reserved_value}.')
        self.observed_reserved_value: bytes = observed_reserved_value


class InvalidCloseResponseFileAttributesValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseCreationTimeValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseLastAccessTimeValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseLastWriteTimeValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseChangeTimeValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseAllocationSizeValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseEndofFileValueError(MalformedCloseResponseError):
    pass


class NonEmptyCloseResponseFileAttributesValueError(MalformedCloseResponseError):
    pass


class MalformedTreeDisconnectRequestError(MalformedSMBv2MessageError):
    pass


class MalformedTreeDisconnectResponseError(MalformedSMBv2MessageError):
    pass


class MalformedQueryDirectoryRequestError(MalformedSMBv2MessageError):
    pass


class InvalidQueryDirectoryRequestFileInformationClassValueError(MalformedQueryDirectoryRequestError):
    pass


class InvalidQueryDirectoryFlagsValueError(MalformedQueryDirectoryRequestError):
    pass


class InvalidQueryDirectoryFileIndexValueError(MalformedQueryDirectoryRequestError):
    def __init__(self, observed_file_index_value: int):
        super().__init__(f'Expected file index to be set to zero, observed {observed_file_index_value}.')
        self.observed_file_index_value = observed_file_index_value


class MalformedQueryDirectoryResponseError(MalformedSMBv2MessageError):
    pass
