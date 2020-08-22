from typing import Any, Iterable


class NotImplementedSMBMessageError(NotImplementedError):
    pass


class NotImplementedSMBv2MessageError(NotImplementedSMBMessageError):
    pass


class NotImplementedNegotiateRequestError(NotImplementedSMBv2MessageError):
    pass


class MalformedSMBMessageError(Exception):
    def __init__(
        self,
        message_header: str,
        observed_value: Any,
        expected_value: Any,
        expected_label: str = 'Expected'
    ):
        super().__init__(
            f'{message_header} '
            f'Observed {observed_value}. '
            f'{expected_label} {expected_value}.'
        )

        self.observed_value: Any = observed_value
        self.expected_value: Any = expected_value


class MalformedSMBv2MessageError(MalformedSMBMessageError):
    pass


class IncorrectStructureSizeError(MalformedSMBMessageError):
    def __init__(self, observed_structure_size: int, expected_structure_size: int):
        super().__init__(
            message_header='Incorrect structure size.',
            observed_value=observed_structure_size,
            expected_value=expected_structure_size
        )


class MalformedNegotiateRequestError(MalformedSMBv2MessageError):
    pass


class NoNegotiateDialectsError(MalformedNegotiateRequestError):
    def __init__(self, observed_dialect_count: Any):
        super().__init__(
            message_header='Incorrect number of dialects specified.',
            observed_value=observed_dialect_count,
            expected_value='a positive integer'
        )


class NegotiateRequestCapabilitiesNotEmpty(MalformedNegotiateRequestError):
    def __init__(self, observed_capabilities_value: bytes):
        super().__init__(
            message_header='Bad observed capabilities value.',
            observed_value=observed_capabilities_value,
            expected_value='empty capabilities'
        )


class MalformedNegotiateResponseError(MalformedSMBv2MessageError):
    pass


class MalformedSessionSetupRequestError(MalformedSMBv2MessageError):
    pass


class MalformedSessionSetupResponseError(MalformedSMBv2MessageError):
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
    def __init__(self, observed_create_response_flag_value: int, expected_response_flag_values: Iterable[int]):
        super().__init__(
            message_header='Bad create response flag value.',
            observed_value=observed_create_response_flag_value,
            expected_value=expected_response_flag_values,
            expected_label='Expected any of'
        )


class InvalidCreateResponseActionError(MalformedCreateResponseError):
    def __init__(self, observed_create_action_value: int, expected_create_action_values: Iterable[int]):
        super().__init__(
            message_header='Bad create action value.',
            observed_value=observed_create_action_value,
            expected_value=expected_create_action_values,
            expected_label='Expected any of'
        )


class InvalidCreateResponseFileAttributesError(MalformedCreateResponseError):
    def __init__(self, observed_file_attributes_value: int, expected_file_attribute_values: Iterable[int]):
        super().__init__(
            message_header='Bad file attributes value.',
            observed_value=observed_file_attributes_value,
            expected_value=expected_file_attribute_values,
            expected_label='Expected a combination of'
        )


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
    def __init__(self, observed_reserved_value: bytes, expected_reserved_value: bytes):
        super().__init__(
            message_header='Non-empty `Reserved` value.',
            observed_value=observed_reserved_value,
            expected_value=expected_reserved_value
        )


class NonEmptyReadResponseReserved2ValueError(MalformedReadResponseError):
    def __init__(self, observed_reserved_value: bytes, expected_reserved_value: bytes):
        super().__init__(
            message_header='Non-empty `Reserved2` value.',
            observed_value=observed_reserved_value,
            expected_value=expected_reserved_value
        )


class MalformedCloseRequestError(MalformedSMBv2MessageError):
    pass


class NonEmptyCloseRequestReservedValueError(MalformedCloseRequestError):
    def __init__(self, observed_reserved_value: bytes):
        super().__init__(f'Expected empty `Reserved` value, got {observed_reserved_value}.')
        self.observed_reserved_value: bytes = observed_reserved_value


class InvalidCloseFlagValueError(MalformedCloseRequestError):
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


class MalformedTreeConnectResponseError(MalformedSMBv2MessageError):
    pass


class MalformedTreeConnectRequestError(MalformedSMBv2MessageError):
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


class MalformedWriteRequestError(MalformedSMBv2MessageError):
    pass


class MalformedWriteResponseError(MalformedSMBv2MessageError):
    pass


class MalformedChangeNotifyRequestError(MalformedSMBv2MessageError):
    pass


class MalformedChangeNotifyResponseError(MalformedSMBv2MessageError):
    pass


class CreditsNotAvailable(Exception):
    def __init__(self, num_requested_credits: int):
        super().__init__(f'The request for {num_requested_credits} could not be fulfilled.')
        self.num_requested_credits = num_requested_credits
