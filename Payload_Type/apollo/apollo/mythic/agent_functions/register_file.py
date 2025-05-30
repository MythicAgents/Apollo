from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64

class RegisterFileArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File", 
                display_name="File",
                type=ParameterType.File,
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=True,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="existingFile",
                cli_name="existingFile",
                display_name="Existing File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=True,
                    group_name="Use Existing File"
                )]
            )
        ]

    async def get_files( self, inputMsg: PTRPCDynamicQueryFunctionMessage ) -> PTRPCDynamicQueryFunctionMessageResponse:
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

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


class RegisterFileCommand(CommandBase):
    cmd = "register_file"
    needs_admin = False
    help_cmd = "register_file (modal popup)"
    description = "Register a file to later use in the agent."
    version = 2
    author = "@djhohnstein"
    argument_class = RegisterFileArguments
    attackmapping = ["T1547"]
    attributes = CommandAttributes(
        builtin=True,
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_parameter_group_name() == "Default":
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("file")
            ))
            if file_resp.Success:
                original_file_name = file_resp.Files[0].Filename
            else:
                raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("file")))
            taskData.args.add_arg("file_name", original_file_name, parameter_group_info=[ParameterGroupInfo(
                group_name="Default"
            )])
            taskData.args.add_arg("file_id", taskData.args.get_arg("file"), parameter_group_info=[ParameterGroupInfo(
                group_name="Default"
            )])
            response.DisplayParams = original_file_name
        else:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                Filename=taskData.args.get_arg("existingFile"),
                MaxResults=1,
            ))
            if not file_resp.Success:
                raise Exception("Failed to fetch find file from Mythic (name: {})".format(taskData.args.get_arg("existingFile")))
            response.DisplayParams = file_resp.Files[0].Filename
            taskData.args.add_arg("file_name", file_resp.Files[0].Filename, parameter_group_info=[ParameterGroupInfo(
                group_name="Use Existing File"
            )])
            taskData.args.add_arg("file_id", file_resp.Files[0].AgentFileId, parameter_group_info=[ParameterGroupInfo(
                group_name="Use Existing File"
            )])
            taskData.args.remove_arg("existingFile")

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
