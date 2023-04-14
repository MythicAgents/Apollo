from mythic_container.MythicCommandBase import *
import json


class NetSharesArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="computer",
                cli_name="Computer",
                display_name="Computer",
                type=ParameterType.String,
                description="Computer to enumerate.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    )
                ]),
        ]

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("computer", self.command_line.strip())
        pass

class NetSharesCommand(CommandBase):
    cmd = "net_shares"
    needs_admin = False
    help_cmd = "net_shares [computer]"
    description = "List remote shares and their accessibility of [computer]"
    version = 2
    author = "@djhohnstein"
    argument_class = NetSharesArguments
    attackmapping = ["T1590", "T1069"]
    supported_ui_features = ["net_shares"]
    browser_script = BrowserScript(script_name="net_shares_new", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp