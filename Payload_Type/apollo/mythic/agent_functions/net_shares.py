from mythic_payloadtype_container.MythicCommandBase import *
import json


class NetSharesArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
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
    browser_script = BrowserScript(script_name="net_shares_new", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass