from CommandBase import *
import json


class UnloadAssemblyArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("unload_assembly requires an assembly name to unload.\n\tUsage: {}".format(UnloadAssemblyCommand.help_cmd))
        pass


class UnloadAssemblyCommand(CommandBase):
    cmd = "unload_assembly"
    needs_admin = False
    help_cmd = "unload_assembly [Assembly.exe]"
    description = "Remove an assembly from the list of loaded assemblies."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = UnloadAssemblyArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass