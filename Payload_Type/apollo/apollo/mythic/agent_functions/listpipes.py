from mythic_container.MythicCommandBase import *
import json


class ListPipesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        # No arguments for now; adjust if you want to support remote enumeration
        self.args = []

    async def parse_arguments(self):
        # No arguments needed
        pass

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class ListPipesCommand(CommandBase):
    cmd = "listpipes"
    needs_admin = False
    help_cmd = "listpipes"
    description = "Lists all named pipes on the local system (\\.\pipe)."
    version = 1
    author = "@ToweringDragoon"
    argument_class = ListPipesArguments
    attackmapping = ["T1083"]

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp