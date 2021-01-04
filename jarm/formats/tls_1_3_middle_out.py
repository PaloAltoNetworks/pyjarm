from jarm.constants import TLS_1_3, ALL, REVERSE, MIDDLE_OUT, SUPPORT_1_3
from jarm.formats.common import CommonTLSFormat


class TLS_1_3_Middle_Out(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_3,
            cipher_list=ALL,
            cipher_order=MIDDLE_OUT,
            is_grease=True,
            is_rare_alpn=False,
            support=SUPPORT_1_3,
            extension_order=REVERSE,
        )
