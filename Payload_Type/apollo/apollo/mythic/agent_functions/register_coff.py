from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class RegisterCoffArguments(TaskArguments):

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
            raise Exception("Register_coff requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)


async def registercoff_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    return response


class RegisterCoffCommand(CommandBase):
    cmd = "register_coff"
    attributes=CommandAttributes(
        dependencies=["register_file"]
    )
    needs_admin = False
    help_cmd = "register_coff (modal popup)"
    description = "Import a new COFF into the agent cache."
    version = 2
    script_only = True
    author = "@__Retrospect"
    argument_class = RegisterCoffArguments
    attackmapping = []
    completion_functions = {"registercoff_callback": registercoff_callback}


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            CommandName="register_file",
            SubtaskCallbackFunction="registercoff_callback",
            Params=json.dumps({"file": taskData.args.get_arg("file")})
        ))
        if not response.Success:
            raise Exception("Failed to create subtask: {}".format(response.Error))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
