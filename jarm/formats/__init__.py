from jarm.formats.tls_1_1_middle_out import TLS_1_1_Middle_Out
from jarm.formats.tls_1_2_bottom_half import TLS_1_2_Bottom_Half
from jarm.formats.tls_1_2_forward import TLS_1_2_Forward
from jarm.formats.tls_1_2_middle_out import TLS_1_2_Middle_Out
from jarm.formats.tls_1_2_reverse import TLS_1_2_Reverse
from jarm.formats.tls_1_2_top_half import TLS_1_2_Top_Half
from jarm.formats.tls_1_3_forward import TLS_1_3_Forward
from jarm.formats.tls_1_3_invalid import TLS_1_3_Invalid
from jarm.formats.tls_1_3_middle_out import TLS_1_3_Middle_Out
from jarm.formats.tls_1_3_reverse import TLS_1_3_Reverse

# JARM v1 Format list
# Order is IMPORTANT
V1 = [
    TLS_1_2_Forward,
    TLS_1_2_Reverse,
    TLS_1_2_Top_Half,
    TLS_1_2_Bottom_Half,
    TLS_1_2_Middle_Out,
    TLS_1_1_Middle_Out,
    TLS_1_3_Forward,
    TLS_1_3_Reverse,
    TLS_1_3_Invalid,
    TLS_1_3_Middle_Out,
]
