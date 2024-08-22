from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_store_addArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="base64ticket",
                cli_name="b64ticket",
                display_name="b64ticket",
                type=ParameterType.String,
                description="A base64 encoded kerberos ticket value that will be loaded into the agents ticket store for future use",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                    ),
                ])
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class ticket_store_addCommand(CommandBase):
    cmd = "ticket_store_add"
    needs_admin = False
    help_cmd = "ticket_store_add [b64ticket]"
    description = "Add a kerberos ticket to the agents internal ticket store. Tickets are injected into sacrificial processes when you're impersonating a token (make_token / steal_token). This is because you have a new logon session to put the tickets into without overriding your existing tickets. For safety, do a make_token with junk creds first."
    version = 2
    author = "@drago-qcc"
    argument_class = ticket_store_addArguments
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
