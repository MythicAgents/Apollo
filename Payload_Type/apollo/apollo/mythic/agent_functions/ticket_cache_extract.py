from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_cache_extractArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
             CommandParameter(
            name="service",
            cli_name="service",
            display_name="service",
            type=ParameterType.String,
            description="Service to extract a ticket for, use krbtgt to get the TGT from the session, otherwise use the service name (ex. ldap, cifs, host)",
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
                description="From an elevated context a LUID may be provided to target a specific session to enumerate tickets.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class ticket_cache_extractCommand(CommandBase):
    cmd = "ticket_cache_extract"
    needs_admin = False
    help_cmd = "ticket_cache_extract [service] [luid]"
    description = "extract a ticket for the provided service name from the current or specified luid"
    version = 2
    author = "@drago-qcc"
    argument_class = ticket_cache_extractArguments
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
