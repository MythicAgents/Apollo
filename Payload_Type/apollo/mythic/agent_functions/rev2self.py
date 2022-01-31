from mythic_payloadtype_container.MythicCommandBase import *
import json


class Rev2SelfArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("rev2self takes no command line arguments.")
        pass


class Rev2SelfCommand(CommandBase):
    cmd = "rev2self"
    needs_admin = False
    help_cmd = "rev2self"
    description = "Revert token to implant's primary token."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = Rev2SelfArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass