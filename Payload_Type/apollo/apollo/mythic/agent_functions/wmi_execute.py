from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class WmiExecuteArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                display_name="command",
                type=ParameterType.String,
                description="Should be the full path and arguments of the process to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1
                    ),
                ]),
            CommandParameter(
                name="host",
                cli_name="Host",
                display_name="Host",
                type=ParameterType.String,
                description="Computer to execute the command on. If empty, the current computer.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2
                    ),
                ]),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="username",
                type=ParameterType.String,
                description="username of the account to execute the wmi process as",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=3
                    ),
                ]),
             CommandParameter(
                name="password",
                cli_name="password",
                display_name="password",
                type=ParameterType.String,
                description="plaintext password of the account",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=4
                    ),
                ]),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="domain",
                type=ParameterType.String,
                description="domain name for the account",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=5
                    ),
                ]) 
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class wmiexecuteCommand(CommandBase):
    cmd = "wmiexecute"
    needs_admin = False
    help_cmd = "wmiexecute [command] [host] [username] [password] [domain]"
    description = "Use WMI to execute a command on the local or specified remote system, can also be given optional credentials to impersonate a different user."
    version = 2
    author = "@drago-qcc"
    argument_class = WmiExecuteArguments
    attackmapping = []
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID,Success=True)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
