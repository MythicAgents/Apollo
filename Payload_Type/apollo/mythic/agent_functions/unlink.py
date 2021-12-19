from mythic_payloadtype_container.MythicCommandBase import *
import json


class UnlinkArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "link_info": CommandParameter(name="Connection to Unlink", type=ParameterType.LinkInfo)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class UnlinkCommand(CommandBase):
    cmd = "unlink"
    needs_admin = False
    help_cmd = "unlink (modal popup)"
    description = "Unlinks a callback from the agent."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = UnlinkArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass