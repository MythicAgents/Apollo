from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64
import sys

class RegisterAssemblyArguments(TaskArguments):

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


async def registerasm_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    return response


class RegisterAssemblyCommand(CommandBase):
    cmd = "register_assembly"
    attributes=CommandAttributes(
        dependencies=["register_file"]
    )
    needs_admin = False
    help_cmd = "register_assembly (modal popup)"
    description = "Import a new Assembly into the agent cache."
    version = 2
    script_only = True
    author = "@djhohnstein"
    argument_class = RegisterAssemblyArguments
    attackmapping = []
    completion_functions = {"registerasm_callback": registerasm_callback}


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            CommandName="register_file",
            SubtaskCallbackFunction="registerasm_callback",
            Params=json.dumps({"file": taskData.args.get_arg("file")})
        ))
        if not response.Success:
            raise Exception("Failed to create subtask: {}".format(response.Error))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
