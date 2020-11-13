from CommandBase import *
import json


class RunArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("run requires a path to an executable to run.\n\tUsage: {}".format(RunCommand.help_cmd))
        pass


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run [binary] [arguments]"
    description = "Execute a binary on the target system. This will properly use %PATH% without needing to specify full locations."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RunArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass