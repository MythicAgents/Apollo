from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
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
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RegisterFileArguments
    attackmapping = ["T1547"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        file_resp = await MythicRPC().execute(
            "get_file",
            file_id=task.args.get_arg("file"),
            task_id=task.id,
            get_contents=False)
        if file_resp.status == MythicRPCStatus.Success:
            original_file_name = file_resp.response[0]["filename"]
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(task.args.get_arg("file")))
        
        task.args.add_arg("file_name", original_file_name)

        task.args.add_arg("file_id", task.args.get_arg("file"))
        task.args.add_arg("file_name", original_file_name)
        
        task.display_params = original_file_name
        
        return task

    async def process_response(self, response: AgentResponse):
        pass
