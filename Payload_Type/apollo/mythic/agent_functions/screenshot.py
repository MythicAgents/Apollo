from mythic_payloadtype_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_payloadtype_container.MythicRPC import *
from sRDI import ShellcodeRDI
import base64

class ScreenshotArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
        }

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot [pid] [x86/x64]"
    description = "Take a screenshot of the current desktop."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein")
    attackmapping = ["T1113"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
