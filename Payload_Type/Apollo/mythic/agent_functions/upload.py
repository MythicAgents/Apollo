from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import sys
import base64


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
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    supported_ui_features = ["file_browser:upload"]
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = UploadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        original_file_name = json.loads(task.original_params)['File']
        sys.stdout.flush()
        resp = await MythicRPC().execute("create_file", task_id=task.id,
                                         file=base64.b64encode(task.args.get_arg("file")).decode(),
                                         saved_file_name=original_file_name, delete_after_fetch=False)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("file", resp.response['agent_file_id'])
            task.args.add_arg("file_name", original_file_name)
        else:
            raise Exception(f"Failed to host file: {resp.error}")
        host = task.args.get_arg("host")
        path = task.args.get_arg("path")
        disp_str = ""
        if path is not None and path != "":
            if host is not None and host != "":
                disp_str = "{} to \\\\{}\\{}".format(original_file_name, host, path)
            else:
                disp_str = "{} to {}".format(original_file_name, path)
        else:
            disp_str = original_file_name
        task.display_params = disp_str
        return task

    async def process_response(self, response: AgentResponse):
        pass
