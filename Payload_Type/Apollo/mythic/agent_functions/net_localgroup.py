from CommandBase import *
import json


class NetLocalGroupArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class NetLocalGroupCommand(CommandBase):
    cmd = "net_localgroup"
    needs_admin = False
    help_cmd = "net_localgroup [computer]"
    description = "Get local groups of [computer]. Defaults to localhost."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = NetLocalGroupArguments
    attackmapping = ["T1590", "T1069"]
    browser_script = BrowserScript(script_name="net_localgroup", author="@djhohnstein")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass