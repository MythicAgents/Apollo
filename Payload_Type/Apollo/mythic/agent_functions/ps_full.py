from mythic_payloadtype_container.MythicCommandBase import *
import json


class PsFullArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("ps_full takes no command line arguments.")
        pass


class PsFullCommand(CommandBase):
    cmd = "ps_full"
    needs_admin = False
    help_cmd = "ps_full"
    description = "Get a process listing with verbose details."
    version = 2
    is_exit = False
    is_file_browse = False
    supported_ui_features = ["process_browser:list"]
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PsFullArguments
    attackmapping = []
    browser_script = BrowserScript(script_name="ps_full", author="@djhohnstein")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass