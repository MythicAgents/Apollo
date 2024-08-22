from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_store_purgeArguments(TaskArguments):

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
                description="If supplied all tickets will be removed from the store",
                default_value= False,
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
        if self.get_arg("all") and self.get_arg("serviceName") == "":
            raise Exception("Need serviceName when specifying to not purge all tickets")
        pass


class ticket_store_purgeCommand(CommandBase):
    cmd = "ticket_store_purge"
    needs_admin = False
    help_cmd = "ticket_store_purge [b64ticket] [all]"
    description = "Remove the specified ticket from the ticket store"
    version = 2
    author = "@drago-qcc"
    argument_class = ticket_store_purgeArguments
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
