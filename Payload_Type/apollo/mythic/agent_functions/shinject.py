from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *
import base64


class ShInjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID",
                type=ParameterType.Number,
                description="Process ID to inject into.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Scripted"
                    ),
                ]),
            CommandParameter(
                name="shellcode",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.File,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    ),
                ]),
            CommandParameter(
                name="shellcode-file-id",
                cli_name="FileID",
                display_name="Shellcode File ID",
                description="Used for automation. Ignore.",
                type=ParameterType.String,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Scripted"
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(ShInjectCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)
        pass


class ShInjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Inject shellcode into a remote process."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ShInjectArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "-PID {}".format(task.args.get_arg("pid"))
        if task.args.get_arg("shellcode") != None:
            file_resp = await MythicRPC().execute(
                "get_file",
                file_id=task.args.get_arg("shellcode"),
                task_id=task.id,
                get_contents=False)
            if file_resp.status == MythicRPCStatus.Success:
                original_file_name = file_resp.response[0]["filename"]
            else:
                raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(task.args.get_arg("file")))
            
            task.display_params += " -File {}".format(original_file_name)
            task.args.add_arg("shellcode-file-id", file_resp.response[0]['agent_file_id'])
            task.args.remove_arg("shellcode")
        elif task.args.get_arg("shellcode-file-id") != None and task.args.get_arg("shellcode-file-id") != "":
            task.display_params += " (scripting automation)"
        else:
            raise Exception("No file provided.")
        return task

    async def process_response(self, response: AgentResponse):
        pass
