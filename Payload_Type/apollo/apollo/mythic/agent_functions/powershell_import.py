from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64
import sys

class PowerShellImportArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File", 
                display_name="File",
                type=ParameterType.File)
        ]

    async def parse_arguments(self):
        if (self.command_line[0] != "{"):
            raise Exception("Inject requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)

async def psimport_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    return response


class PowerShellImportCommand(CommandBase):
    cmd = "powershell_import"
    attributes=CommandAttributes(
        dependencies=["register_file"]
    )
    needs_admin = False
    help_cmd = "powershell_import (modal popup)"
    description = "Import a new .ps1 into the agent cache."
    version = 2
    script_only = True
    author = "@djhohnstein"
    argument_class = PowerShellImportArguments
    attackmapping = []
    completion_functions = {"psimport_callback": psimport_callback}

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                        command="register_file", params_dict={"file": task.args.get_arg("file")},
                        subtask_callback_function="psimport_callback")
        if response.status != MythicStatus.Success:
            raise Exception("Failed to create subtask: {}".format(response.error))
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
