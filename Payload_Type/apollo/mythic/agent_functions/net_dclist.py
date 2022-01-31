from mythic_payloadtype_container.MythicCommandBase import *
import json


class NetDCListArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class NetDCListCommand(CommandBase):
    cmd = "net_dclist"
    needs_admin = False
    help_cmd = "net_dclist [domain]"
    description = "Get domain controllers belonging to [domain]. Defaults to current domain."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = NetDCListArguments
    attackmapping = ["T1590"]
    browser_script = BrowserScript(script_name="net_dclist", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass