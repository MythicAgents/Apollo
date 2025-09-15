from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from .execute_pe import PRINTSPOOFER_FILE_ID
from mythic_container.MythicRPC import *
from os import path
import base64
import tempfile
from distutils.dir_util import copy_tree
import shutil
import asyncio
import platform

if platform.system() == 'Windows':
    INTEROP_ASSEMBLY_PATH = "C:\\Mythic\\Apollo\\srv\\ApolloInterop.dll"
else:
    INTEROP_ASSEMBLY_PATH = "/srv/ApolloInterop.dll"
INTEROP_FILE_ID = ""


class InlineAssemblyArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly_name",
                cli_name="Assembly",
                display_name="Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Assembly to execute (e.g., Seatbelt.exe).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
            CommandParameter(
                name="assembly_file",
                display_name="New Assembly",
                type=ParameterType.File,
                description="A new assembly to execute. After uploading once, you can just supply the assembly_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="New Assembly", ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="assembly_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False, group_name="New Assembly", ui_position=2
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require an assembly to execute.\n\tUsage: {}".format(InlineAssemblyCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", maxsplit=1)
            self.add_arg("assembly_name", parts[0])
            self.add_arg("assembly_arguments", "")
            if len(parts) == 2:
                self.add_arg("assembly_arguments", parts[1])

    async def get_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".exe"):
                    file_names.append(f.Filename)
            fileResponse.Success = True
            fileResponse.Choices = file_names
            return fileResponse
        else:
            fileResponse.Error = file_resp.Error
            return fileResponse


class InlineAssemblyCommand(CommandBase):
    cmd = "inline_assembly"
    needs_admin = False
    help_cmd = "inline_assembly [Assembly.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments in a disposable AppDomain. This assembly must first be known by the agent using the `register_assembly` command."
    version = 3
    author = "@thiagomayllart"
    argument_class = InlineAssemblyArguments
    attackmapping = ["T1547"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False,
        dependencies=["register_file"],
    )

    async def build_interop(self):
        global INTEROP_ASSEMBLY_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/ApolloInterop/bin/Release/ApolloInterop.dll".format(agent_build_path.name)
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "dotnet build -c release -p:DebugType=None -p:DebugSymbols=false -p:Platform=x64 {}/ApolloInterop/ApolloInterop.csproj -o {}/ApolloInterop/bin/Release/".format(
            agent_build_path.name, agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build ApolloInterop.dll:\n{}".format(stderr.decode() + "\n" + stdout.decode()))
        shutil.copy(outputPath, INTEROP_ASSEMBLY_PATH)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global INTEROP_ASSEMBLY_PATH
        global INTEROP_FILE_ID

        if not path.exists(INTEROP_ASSEMBLY_PATH):
            await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
                TaskID=taskData.Task.ID,
                UpdateStatus=f"building interop code"
            ))
            await self.build_interop()

        if INTEROP_FILE_ID == "":
            with open(INTEROP_ASSEMBLY_PATH, "rb") as f:
                interop_bytes = f.read()
            file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=interop_bytes,
                DeleteAfterFetch=False,
            ))

            if file_resp.Success:
                INTEROP_FILE_ID = file_resp.AgentFileId
            else:
                raise Exception("Failed to register Interop DLL: {}".format(file_resp.Error))
        originalGroupNameIsDefault = taskData.args.get_parameter_group_name() == "Default"
        if taskData.args.get_parameter_group_name() == "New Assembly":
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("assembly_file")
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")

            taskData.args.add_arg("assembly_name", fileSearchResp.Files[0].Filename)
            taskData.args.remove_arg("assembly_file")
            taskData.args.add_arg("assembly_id", fileSearchResp.Files[0].AgentFileId)

        taskData.args.add_arg("interop_id", INTEROP_FILE_ID)
        if originalGroupNameIsDefault:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                Filename=taskData.args.get_arg("assembly_name"),
                TaskID=taskData.Task.ID,
                MaxResults=1
            ))
            if not file_resp.Success:
                raise Exception(f"failed to find assembly: {file_resp.Error}")
            if len(file_resp.Files) == 0:
                raise Exception(f"no assembly by that name that's not deleted")
            else:
                taskData.args.add_arg("assembly_id", file_resp.Files[0].AgentFileId)
            response.DisplayParams = "-Assembly {} -Arguments {}".format(
                taskData.args.get_arg("assembly_name"),
                taskData.args.get_arg("assembly_arguments")
            )

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
