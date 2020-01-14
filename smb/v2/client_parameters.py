from smb.v2.structures.dialect import Dialect
from uuid import uuid1

from smb.v2.structures.security_mode import SecurityMode

REQUIRE_MESSAGE_SIGNING = False
IS_ENCRYPTION_SUPPORTED = False
IS_COMPRESSION_SUPPORTED = False
PREFERRED_DIALECT = Dialect.SMB_2_1
CLIENT_GUID = uuid1()
SECURITY_MODE = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
