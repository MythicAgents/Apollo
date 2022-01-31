from mythic_payloadtype_container.MythicCommandBase import *
import json


class StealTokenArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("steal_token requires a PID to steal a token from.")
        try:
            int(self.command_line)
        except:
            raise Exception(f"Invalid integer value given for PID: {self.command_line}")
        if int(self.command_line) % 4 != 0:
            raise Exception(f"Invalid PID given: {self.command_line}. Must be divisible by 4.")
        pass


class StealTokenCommand(CommandBase):
    cmd = "steal_token"
    needs_admin = False
    help_cmd = "steal_token [pid]"
    description = "Steal a primary token from another process. If no arguments are provided, this will default to winlogon.exe."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = StealTokenArguments
    attackmapping = ["T1134", "T1528"]
    supported_ui_features=["steal_token"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass