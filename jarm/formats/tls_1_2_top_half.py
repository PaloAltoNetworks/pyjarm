from jarm.constants import TLS_1_2, ALL, TOP_HALF, FORWARD, NO_SUPPORT
from jarm.formats.common import CommonTLSFormat


class TLS_1_2_Top_Half(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_2,
            cipher_list=ALL,
            cipher_order=TOP_HALF,
            is_grease=False,
            is_rare_alpn=False,
            support=NO_SUPPORT,
            extension_order=FORWARD,
        )
