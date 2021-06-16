from CommandBase import *
import json


class SetInjectionTechniqueArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("set_injection_technique requires an injection technique listed from get_injection_technique to be passed via the command line.\n\tUsage: {}".format(SetInjectionTechniqueCommand.help_cmd))
        pass


class SetInjectionTechniqueCommand(CommandBase):
    cmd = "set_injection_technique"
    needs_admin = False
    help_cmd = "set_injection_technique [technique]"
    description = "Set the injection technique used in post-ex jobs that require injection. Must be a technique listed in the output of `list_injection_techniques`."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = SetInjectionTechniqueArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass