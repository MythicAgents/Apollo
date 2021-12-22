from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *

class ShellArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("shell requires at least one command-line parameter.\n\tUsage: {}".format(ShellCommand.help_cmd))
        pass


class ShellCommand(CommandBase):
    cmd = "shell"
    attributes=CommandAttributes(
        dependencies=["run"]
    )
    needs_admin = False
    help_cmd = "shell [command] [arguments]"
    description = "Run a shell command which will translate to a process being spawned with command line: `cmd.exe /C [command]`"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ShellArguments
    script_only = True
    attackmapping = ["T1059"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                        command="run", params_string="cmd.exe /S /c {}".format(task.args.command_line))
        return task

    async def process_response(self, response: AgentResponse):
        pass