from mythic_container.MythicCommandBase import *
import json


class PowershellArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="command",
            #     cli_name="Command",
            #     display_name="Command",
            #     type=ParameterType.String,
            #     description="Command to run.",
            # ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("At least one command on the command line must be passed to PowerShell.")
        self.add_arg("command", self.command_line)
        pass


class PowershellCommand(CommandBase):
    cmd = "powershell"
    needs_admin = False
    help_cmd = "powershell [command]"
    description = "Run a PowerShell command in the currently executing process."
    version = 2
    author = "@djhohnstein"
    argument_class = PowershellArguments
    attackmapping = ["T1059"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp