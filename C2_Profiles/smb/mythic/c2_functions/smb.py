from mythic_c2_container.C2ProfileBase import *


class SMB(C2Profile):
    name = "smb"
    description = "Communication over SMB named pipes."
    author = "@djhohnstein"
    is_p2p = True
    is_server_routed = True
    parameters = [
        C2ProfileParameter(
            name="pipename",
            description="Named Pipe",
            format_string="[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}",
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
