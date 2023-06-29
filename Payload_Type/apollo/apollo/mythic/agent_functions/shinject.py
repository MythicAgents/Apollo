from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
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
    author = "@djhohnstein"
    argument_class = ShInjectArguments
    attackmapping = ["T1055"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "-PID {}".format(taskData.args.get_arg("pid"))
        if taskData.args.get_arg("shellcode") is not None:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                AgentFileID=taskData.args.get_arg("shellcode"),
                TaskID=taskData.Task.ID,
            ))
            if file_resp.Success:
                original_file_name = file_resp.Files[0].Filename
            else:
                raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("shellcode")))

            response.DisplayParams += " -File {}".format(original_file_name)
            taskData.args.add_arg("shellcode-file-id", file_resp.Files[0].AgentFileId)
            taskData.args.remove_arg("shellcode")
        elif taskData.args.get_arg("shellcode-file-id") is not None and taskData.args.get_arg("shellcode-file-id") != "":
            response.DisplayParams += " (scripting automation)"
        else:
            raise Exception("No file provided.")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
