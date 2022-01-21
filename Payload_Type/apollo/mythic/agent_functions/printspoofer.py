from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64


class PrintSpooferArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="command",
            #     cli_name="Command",
            #     display_name="Command(s)",
            #     type=ParameterType.String,
            #     description="PrintSpoofer command to run (can be one or more)."),
        ]

    async def parse_arguments(self):
        if len(self.command_line):
            self.add_arg("command", "printspoofer.exe {}".format(self.command_line))
        else:
            raise Exception("No PrintSpoofer command given to execute.\n\tUsage: {}".format(PrintSpooferCommand.help_cmd))


class PrintSpooferCommand(CommandBase):
    cmd = "printspoofer"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    needs_admin = False
    help_cmd = "printspoofer [args]"
    description = "Execute one or more PrintSpoofer commands"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PrintSpooferArguments
    attackmapping = ["T1547"]
    script_only = True

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                        command="execute_pe", params_string=task.args.get_arg("command"))
        task.display_params = "-Command {}".format(task.args.get_arg("command"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
