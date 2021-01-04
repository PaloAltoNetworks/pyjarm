from jarm.constants import TLS_1_2, ALL, REVERSE, FORWARD, SUPPORT_1_2
from jarm.formats.common import CommonTLSFormat


class TLS_1_2_Forward(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_2,
            cipher_list=ALL,
            cipher_order=FORWARD,
            is_grease=False,
            is_rare_alpn=False,
            support=SUPPORT_1_2,
            extension_order=REVERSE,
        )
