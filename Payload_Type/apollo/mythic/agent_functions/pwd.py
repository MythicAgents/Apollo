from mythic_payloadtype_container.MythicCommandBase import *
import json


class PwdArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) > 0:
            raise Exception("pwd takes no command line arguments.")
        pass


class PwdCommand(CommandBase):
    cmd = "pwd"
    needs_admin = False
    help_cmd = "pwd"
    description = "Print working directory."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PwdArguments
    attackmapping = ["T1083"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass