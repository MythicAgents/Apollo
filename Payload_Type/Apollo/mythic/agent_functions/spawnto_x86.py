from CommandBase import *
import json


class Spawntox86Arguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("spawnto_x86 requires a path to an executable to be passed on the command line.")
        pass


class Spawntox86Command(CommandBase):
    cmd = "spawnto_x86"
    needs_admin = False
    help_cmd = "spawnto_x86 [path]"
    description = "Change the default binary used in post exploitation jobs to [path]."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = Spawntox86Arguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass