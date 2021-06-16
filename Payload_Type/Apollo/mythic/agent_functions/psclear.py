from CommandBase import *
import json


class PsClearArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("psclear takes no command line arguments.")
        pass


class PsClearCommand(CommandBase):
    cmd = "psclear"
    needs_admin = False
    help_cmd = "psclear"
    description = "Clears all PowerShell scripts known to the agent that were imported by `psimport`."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PsClearArguments
    attackmapping = ["T1059"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass