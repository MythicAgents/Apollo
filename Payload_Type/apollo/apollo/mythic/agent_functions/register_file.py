from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64

class RegisterFileArguments(TaskArguments):

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
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class RegisterFileCommand(CommandBase):
    cmd = "register_file"
    needs_admin = False
    help_cmd = "register_assembly (modal popup)"
    description = "Register a file to later use in the agent."
    version = 2
    author = "@djhohnstein"
    argument_class = RegisterFileArguments
    attackmapping = ["T1547"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            AgentFileID=taskData.args.get_arg("file")
        ))
        if file_resp.Success:
            original_file_name = file_resp.Files[0].Filename
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("file")))
        
        taskData.args.add_arg("file_name", original_file_name)

        taskData.args.add_arg("file_id", taskData.args.get_arg("file"))
        taskData.args.add_arg("file_name", original_file_name)
        
        response.DisplayParams = original_file_name
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
