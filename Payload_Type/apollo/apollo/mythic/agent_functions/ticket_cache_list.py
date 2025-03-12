from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class ticket_cache_listArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="luid",
                default_value="",
                type=ParameterType.String,
                description="From an elevated context a LUID may be provided to target a specific session to enumerate tickets.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1,
                    ),
                ]),
            CommandParameter(
                name="getSystemTickets",
                cli_name="getSystemTickets",
                display_name="Get System Tickets",
                type=ParameterType.Boolean,
                default_value=True,
                description="Set this to false to filter out tickets for the SYSTEM context",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class ticket_cache_listCommand(CommandBase):
    cmd = "ticket_cache_list"
    needs_admin = False
    help_cmd = "ticket_cache_list [luid]"
    description = "List all kerberos tickets in the current logon session, or if elevated list all tickets for all logon sessions, optionally while elevated a single luid can be provided to limit the enumeration"
    version = 2
    author = "@drago-qcc"
    supported_ui_features = ["apollo:ticket_cache_list"]
    argument_class = ticket_cache_listArguments
    attackmapping = []
    attributes = CommandAttributes(
        suggested_command=True
    )
    browser_script = BrowserScript(
        script_name="ticket_cache_list", author="@its_a_feature_", for_new_ui=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID,Success=True)
        getSystemTickets = taskData.args.get_arg("getSystemTickets")
        response.DisplayParams = ""
        luid = taskData.args.get_arg("luid")
        response.DisplayParams += f" -getSystemTickets {getSystemTickets}"
        if luid != "":
            response.DisplayParams += f" -luid {luid}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
