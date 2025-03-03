from mythic_container.MythicCommandBase import *
import json


class GetSystemArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("getsystem takes no command line arguments.")


class GetSystemCommand(CommandBase):
    cmd = "getsystem"
    needs_admin = True
    help_cmd = "getsystem"
    description = "Open a handle to winlogon and duplicate the token."
    version = 2
    author = "@its_a_feature_"
    argument_class = GetSystemArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp