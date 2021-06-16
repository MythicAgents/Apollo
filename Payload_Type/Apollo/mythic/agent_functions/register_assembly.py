from CommandBase import *
import json
from MythicFileRPC import *


class RegisterAssemblyArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "assembly": CommandParameter(name="Assembly", type=ParameterType.File)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class RegisterAssemblyCommand(CommandBase):
    cmd = "register_assembly"
    needs_admin = False
    help_cmd = "register_assembly (modal popup)"
    description = "Register an assembly with the agent to execute later in `execute_assembly`."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = RegisterAssemblyArguments
    attackmapping = ["T1547"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        original_file_name = json.loads(task.original_params)['Assembly']
        resp = await MythicFileRPC(task).register_file(task.args.get_arg("assembly"), saved_file_name=original_file_name)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("assembly_id", resp.agent_file_id)
            task.args.add_arg("assembly_name", original_file_name)
            task.args.remove_arg("assembly")
        else:
            raise Exception(f"Failed to host assembly: {resp.error_message}")
        
        return task

    async def process_response(self, response: AgentResponse):
        pass