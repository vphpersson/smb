from __future__ import annotations
from enum import IntEnum
from dataclasses import dataclass
from typing import Union, Optional
from struct import unpack as struct_unpack, pack as struct_pack

from smb.status import Status


class Severity(IntEnum):
    STATUS_SEVERITY_SUCCESS = 0x0
    STATUS_SEVERITY_INFORMATIONAL = 0x1
    STATUS_SEVERITY_WARNING = 0x2
    STATUS_SEVERITY_ERROR = 0x3


class Customer(IntEnum):
    CUSTOMER_DEFINED = 1
    MICROSOFT_DEFINED = 0


class Facility(IntEnum):
    pass


class MicrosoftFacility(Facility):
    _FACILITY_NONE = 0x00
    FACILITY_DEBUGGER = 0x001
    FACILITY_RPC_RUNTIME = 0x002
    FACILITY_RPC_STUBS = 0x003
    FACILITY_IO_ERROR_CODE = 0x004
    FACILITY_NTWIN32 = 0x007
    FACILITY_NTSSPI = 0x009
    FACILITY_TERMINAL_SERVER = 0x00A
    FACILTIY_MUI_ERROR_CODE = 0x00B
    FACILITY_USB_ERROR_CODE = 0x010
    FACILITY_HID_ERROR_CODE = 0x011
    FACILITY_FIREWIRE_ERROR_CODE = 0x012
    FACILITY_CLUSTER_ERROR_CODE = 0x013
    FACILITY_ACPI_ERROR_CODE = 0x014
    FACILITY_SXS_ERROR_CODE = 0x015
    FACILITY_TRANSACTION = 0x019
    FACILITY_COMMONLOG = 0x01A
    FACILITY_VIDEO = 0x01B
    FACILITY_FILTER_MANAGER = 0x01C
    FACILITY_MONITOR = 0x01D
    FACILITY_GRAPHICS_KERNEL = 0x01E
    FACILITY_DRIVER_FRAMEWORK = 0x020
    FACILITY_FVE_ERROR_CODE = 0x021
    FACILITY_FWP_ERROR_CODE = 0x022
    FACILITY_NDIS_ERROR_CODE = 0x023
    FACILITY_HYPERVISOR = 0x035
    FACILITY_IPSEC = 0x036
    FACILITY_MAXIMUM_VALUE = 0x037


@dataclass
class NTSTATUS:
    severity: Severity
    customer: Customer
    _n: int
    facility: Union[Facility, int]
    code: int

    _real_status: Optional[Status]

    @classmethod
    def from_bytes(cls, data: bytes) -> NTSTATUS:
        ntstatus_mask: int = struct_unpack('<I', data[:4])[0]

        n: int = (ntstatus_mask & (2**29 - 2**28)) >> 28
        if n != 0:
            # TODO: Use a proper exception.
            raise ValueError('n is not 0')

        customer = Customer((ntstatus_mask & (2**30 - 2**29)) >> 29)
        raw_facility_value = (ntstatus_mask & (2**28 - 2**16)) >> 16
        facility = raw_facility_value if Customer.CUSTOMER_DEFINED else MicrosoftFacility(raw_facility_value)

        try:
            real_status = Status(ntstatus_mask)
        except ValueError:
            real_status = None

        return cls(
            # TODO: This could probably be done in a more efficient way. ;)
            severity=Severity((ntstatus_mask & (2**32 - 2**30)) >> 30),
            customer=customer,
            _n=0,
            facility=facility,
            code=ntstatus_mask & 2**16,
            _real_status=real_status
        )

    @property
    def real_status(self) -> Optional[Status]:
        return self._real_status

    def __bytes__(self) -> bytes:
        mask = 0
        mask |= (self.severity.value << 30)
        mask |= (self.customer.value << 29)
        mask |= (self._n << 28)
        mask |= (int(self.facility) << 16)
        mask |= self.code

        return struct_pack('<I', mask)


