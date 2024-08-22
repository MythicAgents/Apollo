from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_cache_purgeArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="serviceName",
                cli_name="serviceName",
                display_name="serviceName",
                type=ParameterType.String,
                description="the name of the service to remove, needs to include the domain name, is required if -all flag is not present",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1,
                    ),
                ]),
            CommandParameter(
                name="all",
                cli_name="all",
                display_name="all",
                type=ParameterType.Boolean,
                description="If supplied all tickets will be removed from the current LUID on the system",
                default_value= False,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
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
                        ui_position=3,
                    ),
                ])
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        if self.get_arg("all") and self.get_arg("serviceName") == "":
            raise Exception("Need serviceName when specifying to not purge all tickets")
        pass


class ticket_cache_purgeCommand(CommandBase):
    cmd = "ticket_cache_purge"
    needs_admin = False
    help_cmd = "ticket_cache_purge -serviceName=krbtgt/domain.com"
    description = "Remove the specified ticket from the system. This modifies your current logon session tickets, so be careful if purging all."
    version = 2
    author = "@drago-qcc"
    argument_class = ticket_cache_purgeArguments
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
