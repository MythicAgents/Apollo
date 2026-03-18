from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64

class ListRegisteredFilesArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [

        ]
    async def parse_arguments(self):
        pass


class ListRegisteredFilesCommand(CommandBase):
    cmd = "list_registered_files"
    needs_admin = False
    help_cmd = "list_registered_files"
    description = "List the files currently registered within the agent."
    version = 2
    author = "@its_a_feature_"
    argument_class = ListRegisteredFilesArguments
    attackmapping = []
    attributes = CommandAttributes(
        builtin=True,
        suggested_command=True
    )
    browser_script = BrowserScript(script_name="list_registered_files", author="@its_a_feature_")

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
