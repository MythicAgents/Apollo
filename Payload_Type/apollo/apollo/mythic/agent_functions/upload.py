from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import re


class UploadArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote_path",
                cli_name="Path",
                display_name="Path With Filename",
                type=ParameterType.String,
                description="Path to write the file on the target. If empty, defaults to current working directory.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="ExistingFile",
                        ui_position=2
                    ),
                ],
            ),
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="File",
                type=ParameterType.File,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    ),
                ],
            ),
            CommandParameter(
                name="filename",
                cli_name="fileName",
                display_name="Existing File Name",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Name of file that Mythic is already tracking (e.g., Seatbelt.exe).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="ExistingFile", ui_position=1
                    )
                ],
            ),
        ]

    async def get_files(
        self, inputMsg: PTRPCDynamicQueryFunctionMessage
    ) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                CallbackID=inputMsg.Callback,
                LimitByCallback=False,
                Filename="",
            )
        )
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names:
                    file_names.append(f.Filename)
            fileResponse.Success = True
            fileResponse.Choices = file_names
            return fileResponse
        else:
            fileResponse.Error = file_resp.Error
            return fileResponse

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)
        if "host" in dictionary_arguments:
            if 'remote_path' in dictionary_arguments:
                if dictionary_arguments['remote_path'].startswith("\\\\") or ":\\" in dictionary_arguments['remote_path']:
                    # remote_path includes UNC path or some full directory, just use it
                    pass
                else:
                    new_path = dictionary_arguments["full_path"].rstrip("\\") + "\\" + dictionary_arguments["remote_path"]
                    self.add_arg("remote_path", f'\\\\{dictionary_arguments["host"]}\\{new_path}')
            else:
                if "full_path" in dictionary_arguments:
                    self.add_arg("remote_path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["full_path"]}')
                elif "path" in dictionary_arguments:
                    self.add_arg("remote_path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["path"]}')
                elif "file" in dictionary_arguments:
                    self.add_arg("remote_path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["file"]}')
                else:
                    logger.info("unknown dictionary args")

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        remote_path = self.get_arg("remote_path")
        if remote_path != "" and remote_path is not None:
            remote_path = remote_path.strip()
            if remote_path[0] == '"' and remote_path[-1] == '"':
                remote_path = remote_path[1:-1]
            elif remote_path[0] == "'" and remote_path[-1] == "'":
                remote_path = remote_path[1:-1]
            self.add_arg("remote_path", remote_path)


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
    attributes = CommandAttributes(suggested_command=True)

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        originalGroupName = taskData.args.get_parameter_group_name()
        if originalGroupName == "Default":
            file_resp = await SendMythicRPCFileSearch(
                MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID, AgentFileID=taskData.args.get_arg("file")
                )
            )
            if file_resp.Success:
                original_file_name = file_resp.Files[0].Filename
            else:
                raise Exception(
                    "Failed to fetch uploaded file from Mythic (ID: {})".format(
                        taskData.args.get_arg("file")
                    )
                )
            taskData.args.add_arg(
                "file_name", original_file_name, type=ParameterType.String,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name=originalGroupName, ui_position=1
                    )
                ],
            )
        else:
            original_file_name = taskData.args.get_arg("filename")
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                Filename=taskData.args.get_arg("filename"),
                TaskID=taskData.Task.ID,
                MaxResults=1
            ))
            if not file_resp.Success:
                raise Exception(f"failed to find file: {file_resp.Error}")
            if len(file_resp.Files) == 0:
                raise Exception(f"no file by that name that's not deleted")
            taskData.args.remove_arg("file")
            taskData.args.remove_arg("filename")
            taskData.args.add_arg("file", file_resp.Files[0].AgentFileId,
                                  parameter_group_info=[
                                      ParameterGroupInfo(
                                          required=True, group_name=originalGroupName, ui_position=1
                                      )
                                  ],)
        path = taskData.args.get_arg("remote_path")
        if path is None or path == "":
            path = original_file_name
            taskData.args.add_arg("remote_path", path, parameter_group_info=[
                ParameterGroupInfo(
                    required=True, group_name=originalGroupName, ui_position=1
                )
            ])
            taskData.args.add_arg("host", taskData.Callback.Host, parameter_group_info=[
                ParameterGroupInfo(
                    required=True, group_name=originalGroupName, ui_position=1
                )
            ])
        if uncmatch := re.match(
            r"^\\\\(?P<host>[^\\]+)\\(?P<path>.*)$",
            path,
        ):
            taskData.args.add_arg("host", uncmatch.group("host"), parameter_group_info=[
                ParameterGroupInfo(
                    required=True, group_name=originalGroupName, ui_position=1
                )
            ])
            taskData.args.set_arg("remote_path", uncmatch.group("path"))
        else:
            # Set the host argument to an empty string if it does not exist
            taskData.args.add_arg("host", taskData.Callback.Host, parameter_group_info=[
                ParameterGroupInfo(
                    required=True, group_name=originalGroupName, ui_position=1
                )
            ])
        if host := taskData.args.get_arg("host"):
            host = host.upper()

            # Resolve 'localhost' and '127.0.0.1' aliases
            if host == "127.0.0.1" or host.lower() == "localhost":
                host = taskData.Callback.Host

            taskData.args.set_arg("host", host)
        if path is not None and path != "":
            if host is not None and host != "":
                disp_str = "-fileName {} -Host {} -Path {}".format(
                    original_file_name, taskData.args.get_arg("host"), taskData.args.get_arg("remote_path")
                )
            else:
                disp_str = "-fileName {} -Path {}".format(original_file_name, taskData.args.get_arg("remote_path"))
        else:
            disp_str = "-fileName {}".format(original_file_name)
        response.DisplayParams = disp_str
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
