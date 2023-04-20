from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class ShellArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception(
                "shell requires at least one command-line parameter.\n\tUsage: {}".format(ShellCommand.help_cmd))
        pass


class ShellCommand(CommandBase):
    cmd = "shell"
    attributes = CommandAttributes(
        dependencies=["run"],
        suggested_command=True
    )
    needs_admin = False
    help_cmd = "shell [command] [arguments]"
    description = "Run a shell command which will translate to a process being spawned with command line: `cmd.exe /C [command]`"
    version = 2
    author = "@djhohnstein"
    argument_class = ShellArguments
    script_only = True
    attackmapping = ["T1059"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            CommandName="run",
            Params="cmd.exe /S /c {}".format(taskData.args.command_line)
        ))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
