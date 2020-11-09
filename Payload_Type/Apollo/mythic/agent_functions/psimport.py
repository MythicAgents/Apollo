from CommandBase import *
import json
from MythicFileRPC import *


class PsImportArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "file": CommandParameter(name="PowerShell Script", type=ParameterType.File)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No script given to import.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON arguments, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class PsImportCommand(CommandBase):
    cmd = "psimport"
    needs_admin = False
    help_cmd = "psimport (modal popup)"
    description = """Register a PowerShell script to import on subsequent execution in `powerpick`/`psinject`/`powershell` commands. Can import more than one script (e.g., PowerView and PowerUp can both be loaded simultaneously.) To clear the script imports, use `psclear`."""
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PsImportArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        original_file_name = json.loads(task.original_params)['PowerShell Script']
        resp = await MythicFileRPC(task).register_file(task.args.get_arg("file"), saved_file_name=original_file_name)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("file_id", resp.agent_file_id)
            task.args.remove_arg("file")
            task.args.add_arg("file_name", original_file_name)
        else:
            raise Exception(f"Failed to host file: {resp.error_message}")
        return task

    async def process_response(self, response: AgentResponse):
        pass