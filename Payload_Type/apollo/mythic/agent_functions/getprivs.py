from mythic_payloadtype_container.MythicCommandBase import *
import json


class GetPrivsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("getprivs takes no command line arguments.")


class GetPrivsCommand(CommandBase):
    cmd = "getprivs"
    needs_admin = False
    help_cmd = "getprivs"
    description = "Enable as many privileges as we can on our current thread token."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = GetPrivsArguments
    attackmapping = ["T1078"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass