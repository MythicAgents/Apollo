from mythic_container.MythicCommandBase import *
import json


class IfconfigArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("ifconfig takes no command line arguments.")
        pass


class IfconfigCommand(CommandBase):
    cmd = "ifconfig"
    needs_admin = False
    help_cmd = "ifconfig"
    description = "Get interface information associated with the target."
    version = 1
    author = "@thespicybyte"
    argument_class = IfconfigArguments
    attackmapping = ["T1590.005"]
    browser_script = BrowserScript(script_name="ifconfig", author="@thespicybyte", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
