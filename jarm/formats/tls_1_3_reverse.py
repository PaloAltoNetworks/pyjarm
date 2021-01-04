from jarm.constants import TLS_1_3, ALL, REVERSE, FORWARD, SUPPORT_1_3
from jarm.formats.common import CommonTLSFormat


class TLS_1_3_Reverse(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_3,
            cipher_list=ALL,
            cipher_order=REVERSE,
            is_grease=False,
            is_rare_alpn=False,
            support=SUPPORT_1_3,
            extension_order=FORWARD,
        )
