from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64


class UploadArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote_path",
                cli_name="Destination",
                display_name="Destination",
                type=ParameterType.String,
                description="Path to write the file on the target. If empty, defaults to current working directory.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="File",
                type=ParameterType.File),
            CommandParameter(
                name="host",
                cli_name="Host",
                display_name="Host",
                type=ParameterType.String,
                description="Computer to upload the file to. If empty, the current computer.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        remote_path = self.get_arg("remote_path")
        if remote_path != "" and remote_path != None:
            remote_path = remote_path.strip()
            if remote_path[0] == '"' and remote_path[-1] == '"':
                remote_path = remote_path[1:-1]
            elif remote_path[0] == "'" and remote_path[-1] == "'":
                remote_path = remote_path[1:-1]
            self.add_arg("remote_path", remote_path)
        pass


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload (modal popup)"
    description = "Upload a file from the Mythic server to the remote host."
    version = 2
    supported_ui_features = ["file_browser:upload"]
    author = "@djhohnstein"
    argument_class = UploadArguments
    attackmapping = ["T1132", "T1030", "T1105"]
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            AgentFileID=taskData.args.get_arg("file")
        ))
        if file_resp.Success:
            original_file_name = file_resp.Files[0].Filename
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("file")))

        taskData.args.add_arg("file_name", original_file_name, type=ParameterType.String)
        host = taskData.args.get_arg("host")
        path = taskData.args.get_arg("remote_path")
        if path is not None and path != "":
            if host is not None and host != "":
                disp_str = "-File {} -Host {} -Path {}".format(original_file_name, host, path)
            else:
                disp_str = "-File {} -Path {}".format(original_file_name, path)
        else:
            disp_str = "-File {}".format(original_file_name)
        response.DisplayParams = disp_str
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
