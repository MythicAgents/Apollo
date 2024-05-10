from distutils.dir_util import copy_tree
from mythic_container.MythicCommandBase import *
from uuid import uuid4
from mythic_container.MythicRPC import *
from os import path
import shutil
import tempfile
import asyncio
import platform

if platform.system() == 'Windows':  
    RUNOF_HOST_PATH= "C:\\Mythic\\Apollo\\srv\\RunOF.dll"
else:
    RUNOF_HOST_PATH= "/srv/RunOF.dll"
RUNOF_FILE_ID=""


class ExecuteCoffArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="coff_name",
                cli_name="Coff",
                display_name="Coff",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="COFF to execute (e.g. whoami.x64.o)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
            CommandParameter(
                name="function_name",
                cli_name="Function",
                display_name="Function",
                type=ParameterType.String,
                default_value="go",
                description="Entry function name.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                ]),
            CommandParameter(
                name="timeout",
                cli_name="Timeout",
                display_name="Timeout",
                type=ParameterType.String,
                default_value="30",
                description="Set thread timeout (in seconds).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    ),
                ]),
            CommandParameter(
                name="coff_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int16", "int32", "string", "wchar", "base64"],
                description="""Arguments to pass to the COFF via the following way:
                -s:123 or int16:123
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or base64:abc==""",
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4
                    ),
                ]),
        ]

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True)
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)
        coff_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s":
                coff_arguments.append(["int16",int(value)])
            elif argType == "int32" or argType == "-i":
                coff_arguments.append(["int32",int(value)])
            elif argType == "string" or argType == "-z":
                coff_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z":
                coff_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b":
                coff_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False, Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=coff_arguments)
        return argumentResponse

    async def get_files(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=inputMsg.Callback,
            LimitByCallback=True,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".o"):
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
            raise Exception("Require a BOFF, Function Name and Timeout to execute.\n\tUsage: {}".format(ExecuteCoffCommand.help_cmd))

class ExecuteCoffCommand(CommandBase):
    cmd = "execute_coff"
    needs_admin = False
    help_cmd = "execute_coff -Coff [COFF.o] -Function [go] -Timeout [30] [-Arguments [optional arguments]]"
    description = "Execute a COFF file in memory. This COFF must first be known by the agent using the `register_coff` command."
    version = 3
    author = "@__Retrospect"
    argument_class = ExecuteCoffArguments
    attackmapping = ["T1559"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False
    )

    async def build_runof(self):
        global RUNOF_HOST_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/RunOF/bin/Release/RunOF.dll".format(agent_build_path.name)
        # shutil to copy payload files over
        copy_tree(str(self.agent_code_path), agent_build_path.name)
        shell_cmd = "dotnet build -c release -p:Platform=x64 {}/RunOF/RunOF.csproj -o {}/RunOF/bin/Release/".format(agent_build_path.name, agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build RunOF.dll:\n{}".format(stderr.decode() + "\n" + stdout.decode()))
        shutil.copy(outputPath, RUNOF_HOST_PATH)

    async def registered_runof(self, taskData: PTTaskMessageAllData) -> str:
        global RUNOF_HOST_PATH
        if not path.exists(RUNOF_HOST_PATH):
            await self.build_runof()
        fileSearch = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            Filename="RunOF.dll",
            LimitByCallback=True,
            MaxResults=1
        ))
        if not fileSearch.Success:
            raise Exception(fileSearch.Error)
        if len(fileSearch.Files) == 0:
            fileRegister = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=open(RUNOF_HOST_PATH, 'rb').read(),
                DeleteAfterFetch=False,
                Filename="RunOF.dll",
                IsScreenshot=False,
                IsDownloadFromAgent=False,
                Comment=f"Shared RunOF.dll for all execute_coff tasks within Callback {taskData.Callback.DisplayID}"
            ))
            if fileRegister.Success:
                return fileRegister.AgentFileId
            raise Exception(fileRegister.Error)
        return fileSearch.Files[0].AgentFileId

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID, Success=True)
        registered_runof_id = await self.registered_runof(taskData)
        taskData.args.add_arg("runof_id", registered_runof_id)
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(TaskID=taskData.Task.ID, Filename=taskData.args.get_arg("coff_name")))
        if file_resp.Success and len(file_resp.Files) > 0:
            taskData.args.add_arg("loader_stub_id", file_resp.Files[0].AgentFileId)
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("coff_name")))

        timeout = taskData.args.get_arg("timeout")
        if timeout is None or timeout == "":
            taskData.args.set_arg("timeout", "30")

        taskargs = taskData.args.get_arg("coff_arguments")
        if taskargs == "" or taskargs is None:
            response.DisplayParams = "-Coff {} -Function {} -Timeout {}".format(
                taskData.args.get_arg("coff_name"),
                taskData.args.get_arg("function_name"),
                taskData.args.get_arg("timeout")
            )
        else:
            response.DisplayParams = "-Coff {} -Function {} -Timeout {} -Arguments {}".format(
                taskData.args.get_arg("coff_name"),
                taskData.args.get_arg("function_name"),
                taskData.args.get_arg("timeout"),
                taskargs
            )

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
