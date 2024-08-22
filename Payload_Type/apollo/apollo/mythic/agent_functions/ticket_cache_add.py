from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_cache_addArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="base64ticket",
                cli_name="b64ticket",
                display_name="b64ticket",
                type=ParameterType.String,
                description="A base64 encoded kerberos ticket value that will be loaded into the current logon session",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                    ),
                ]),
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="luid",
                type=ParameterType.String,
                description="From an elevated context a LUID may be provided to target a specific session to add tickets to.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                    ),
                ])     
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class ticket_cache_addCommand(CommandBase):
    cmd = "ticket_cache_add"
    needs_admin = False
    help_cmd = "ticket_cache_add [b64Ticket] [luid]"
    description = "Add a kerberos ticket to the current luid, or if elevated and a luid is provided load the ticket into that logon session instead. This modifies the tickets in the current logon session."
    version = 2
    author = "@drago-qcc"
    argument_class = ticket_cache_addArguments
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
