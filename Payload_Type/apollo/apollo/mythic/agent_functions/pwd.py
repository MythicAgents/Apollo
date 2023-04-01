from mythic_container.MythicCommandBase import *
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
    author = "@djhohnstein"
    argument_class = PwdArguments
    attackmapping = ["T1083"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp