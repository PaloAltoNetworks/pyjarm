from jarm.constants import TLS_1_3, NO_1_3, FORWARD, SUPPORT_1_3
from jarm.formats.common import CommonTLSFormat


class TLS_1_3_Invalid(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_3,
            cipher_list=NO_1_3,
            cipher_order=FORWARD,
            is_grease=False,
            is_rare_alpn=False,
            support=SUPPORT_1_3,
            extension_order=FORWARD,
        )
