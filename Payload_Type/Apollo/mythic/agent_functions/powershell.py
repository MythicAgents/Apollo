from mythic_payloadtype_container.MythicCommandBase import *
import json


class PowershellArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("At least one command on the command line must be passed to PowerShell.")
        pass


class PowershellCommand(CommandBase):
    cmd = "powershell"
    needs_admin = False
    help_cmd = "powershell [command]"
    description = "Run a PowerShell command in the currently executing process."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PowershellArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass