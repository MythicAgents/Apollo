from mythic_c2_container.C2ProfileBase import *


class TCP(C2Profile):
    name = "tcp"
    description = "Communication over TCP sockets."
    author = "@djhohnstein"
    is_p2p = True
    is_server_routed = True
    parameters = [
        C2ProfileParameter(
            name="port",
            description="Port to start Apollo on.",
            format_string="[0-65535]{1}",
            randomize=True,
            required=False,
        ),
        C2ProfileParameter(
            name="killdate",
            description="Kill Date",
            parameter_type=ParameterType.Date,
            default_value=365,
            required=False,
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform Key Exchange",
            choices=["T", "F"],
            required=False,
            parameter_type=ParameterType.ChooseOne,
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Crypto type",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            required=False,
            crypto_type=True
        ),
    ]
