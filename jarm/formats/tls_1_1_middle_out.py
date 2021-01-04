from jarm.constants import TLS_1_1, ALL, FORWARD, NO_SUPPORT
from jarm.formats.common import CommonTLSFormat


class TLS_1_1_Middle_Out(CommonTLSFormat):
    def __init__(self):
        super().__init__(
            version=TLS_1_1,
            cipher_list=ALL,
            cipher_order=FORWARD,  # Not sure if correct, copied from SFDC source
            is_grease=False,
            is_rare_alpn=False,
            support=NO_SUPPORT,
            extension_order=FORWARD,
        )
