from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64

class RemoveRegisteredFileArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file_name",
                cli_name="filename",
                display_name="File Name",
                type=ParameterType.String,
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("file_name", self.command_line)
        pass


class RemoveRegisteredFileCommand(CommandBase):
    cmd = "remove_registered_file"
    needs_admin = False
    help_cmd = "remove_registered_file -filename RegisteredFile.exe"
    description = "Remove a registered file within the agent"
    version = 2
    author = "@its_a_feature_"
    argument_class = RemoveRegisteredFileArguments
    attackmapping = []
    supported_ui_features = ["apollo:remove_registered_file"]
    attributes = CommandAttributes(
        builtin=True,
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("file_name")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
