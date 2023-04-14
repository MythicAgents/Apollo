from mythic_container.MythicCommandBase import *
import json


class NetLocalGroupArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class NetLocalGroupCommand(CommandBase):
    cmd = "net_localgroup"
    needs_admin = False
    help_cmd = "net_localgroup [computer]"
    description = "Get local groups of [computer]. Defaults to localhost."
    version = 2
    author = "@djhohnstein"
    argument_class = NetLocalGroupArguments
    attackmapping = ["T1590", "T1069"]
    browser_script = BrowserScript(script_name="net_localgroup_new", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp