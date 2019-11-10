from enum import IntEnum


class Dialect(IntEnum):
    SMB_2_0_2 = 0x0202
    SMB_2_1 = 0x0210
    SMB_3_0 = 0x0300
    SMB_3_0_2 = 0x0302
    SMB_3_1_1 = 0x0311
    SMB_2_WILDCARD = 0x02FF

# class ResponseDialect(Dialect):
#     SMB_2_WILDCARD = 0x02FF
