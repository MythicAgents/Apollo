from CommandBase import *
import json


class ListInjectionTechniquesArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("list_injection_techniques takes no parameters.")


class ListInjectionTechniquesCommand(CommandBase):
    cmd = "list_injection_techniques"
    needs_admin = False
    help_cmd = "list_injection_techniques"
    description = "List the currently available injection techniques the agent knows about."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ListInjectionTechniquesArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass