from mythic_payloadtype_container.MythicCommandBase import *
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
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = NetSharesArguments
    attackmapping = ["T1590", "T1069"]
    supported_ui_features = ["net_shares"]
    browser_script = BrowserScript(script_name="net_shares_new", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass