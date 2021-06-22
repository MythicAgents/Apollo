from mythic_payloadtype_container.MythicCommandBase import *
import json


class ListScriptsArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("list_scripts takes no arguments.")


class ListScriptsCommand(CommandBase):
    cmd = "list_scripts"
    needs_admin = False
    help_cmd = "list_scripts"
    description = "List all registered PowerShell scripts that are imported into any task that executes PowerShell."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ListScriptsArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass