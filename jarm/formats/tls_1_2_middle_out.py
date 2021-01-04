from jarm.constants import TLS_1_2, ALL, REVERSE, MIDDLE_OUT, NO_SUPPORT
from jarm.formats.common import CommonTLSFormat


class TLS_1_2_Middle_Out(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_2,
            cipher_list=ALL,
            cipher_order=MIDDLE_OUT,
            is_grease=True,
            is_rare_alpn=True,
            support=NO_SUPPORT,
            extension_order=REVERSE,
        )
