from mythic_c2_container.C2ProfileBase import *


class SMB(C2Profile):
    name = "SMB"
    description = "SMB Server profile to launch a new agent on a named pipe."
    author = "@djhohnstein"
    is_p2p = True
    is_server_routed = True
    notes = """
    When choosing this option, this will additionally compile in the SMBClient profile as well
    """
    parameters = [
        C2ProfileParameter(name="pipename", description="Pipe Name",randomize=True,format_string="[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}"),
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