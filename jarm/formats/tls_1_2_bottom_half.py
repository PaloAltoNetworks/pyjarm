from jarm.constants import TLS_1_2, ALL, BOTTOM_HALF, FORWARD, NO_SUPPORT
from jarm.formats.common import CommonTLSFormat


class TLS_1_2_Bottom_Half(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_2,
            cipher_list=ALL,
            cipher_order=BOTTOM_HALF,
            is_grease=False,
            is_rare_alpn=True,
            support=NO_SUPPORT,
            extension_order=FORWARD,
        )
