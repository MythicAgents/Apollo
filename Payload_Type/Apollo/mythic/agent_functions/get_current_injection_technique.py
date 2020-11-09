from CommandBase import *
import json


class GetCurrentInjectionTechniqueArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("get_current_injection_technique takes no parameters.")


class GetCurrentInjectionTechniqueCommand(CommandBase):
    cmd = "get_current_injection_technique"
    needs_admin = False
    help_cmd = "get_current_injection_technique"
    description = "List the current injection technique used in jobs requiring injection. Default is `CreateRemoteThreadInjection`"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = GetCurrentInjectionTechniqueArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass