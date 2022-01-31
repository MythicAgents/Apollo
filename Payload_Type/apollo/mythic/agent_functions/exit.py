from mythic_payloadtype_container.MythicCommandBase import *
import json


class ExitArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("Exit command takes no parameters.")


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "Task the implant to exit."
    version = 2
    supported_ui_features = ["callback_table:exit"]
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ExitArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass