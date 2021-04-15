from CommandBase import *
import json
from MythicFileRPC import *
import sys


class UploadArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "remote_path": CommandParameter(name="Destination", required=False, type=ParameterType.String,
                              description="Path to write the file on the target. If empty, defaults to current working directory."),
            "file": CommandParameter(name="File", type=ParameterType.File),
            "host": CommandParameter(name="Host", required=False, type=ParameterType.String, description="Computer to upload the file to. If empty, the current computer.")
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        remote_path = self.get_arg("remote_path")
        if remote_path != "" and remote_path != None:
            remote_path = remote_path.strip()
            if remote_path[0] == '"' and remote_path[-1] == '"':
                remote_path = remote_path[1:-1]
            elif remote_path[0] == "'" and remote_path[-1] == "'":
                remote_path = remote_path[1:-1]
            self.add_arg("remote_path", remote_path)
        pass


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload (modal popup)"
    description = "Upload a file from the Apfell server to the remote host."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = True
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = UploadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        original_file_name = json.loads(task.original_params)['File']
        sys.stdout.flush()
        resp = await MythicFileRPC(task).register_file(task.args.get_arg("file"), saved_file_name=original_file_name, delete_after_fetch=False)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("file", resp.agent_file_id)
            task.args.add_arg("file_name", original_file_name)
        else:
            raise Exception(f"Failed to host file: {resp.error_message}")
        
        return task

    async def process_response(self, response: AgentResponse):
        pass

