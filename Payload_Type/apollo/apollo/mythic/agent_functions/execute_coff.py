import binascii
import struct
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import platform
from os import path
import shutil

if platform.system() == 'Windows':
    RUNOF_HOST_PATH = "C:\\Mythic\\Apollo\\srv\\COFFLoader.dll"
else:
    RUNOF_HOST_PATH = "/srv/COFFLoader.dll"
RUNOF_FILE_ID = ""


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
                name="bof_file",
                display_name="New Bof",
                type=ParameterType.File,
                description="A new bof to execute. After uploading once, you can just supply the coff_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, group_name="New", ui_position=1,
                    )
                ]
            ),
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
                    ParameterGroupInfo(
                        required=False,
                        group_name="New",
                        ui_position=2
                    ),
                ]),
            CommandParameter(
                name="timeout",
                cli_name="Timeout",
                display_name="Timeout",
                type=ParameterType.Number,
                default_value=30,
                description="Set thread timeout (in seconds).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New",
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
                    ParameterGroupInfo(
                        required=False,
                        group_name="New",
                        ui_position=4
                    ),
                ]),
        ]

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
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
            elif argType == "int16" or argType == "-s" or argType == "s":
                coff_arguments.append(["int16",int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i":
                coff_arguments.append(["int32",int(value)])
            elif argType == "string" or argType == "-z" or argType == "z":
                coff_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z" or argType == "Z":
                coff_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b" or argType == "b":
                coff_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

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
    author = "@__Retrospect, @its_a_feature_"
    argument_class = ExecuteCoffArguments
    attackmapping = ["T1559"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows],
        builtin=False,
        load_only=False,
        suggested_command=False,
        dependencies=["register_file"],
    )

    async def registered_runof(self, taskData: PTTaskMessageAllData) -> str:
        global RUNOF_HOST_PATH
        if not path.exists(RUNOF_HOST_PATH):
            shutil.move(f"apollo/agent_code/COFFLoader.dll", RUNOF_HOST_PATH)
        fileSearch = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            Filename="COFFLoader.dll",
            LimitByCallback=False,
            MaxResults=1
        ))
        if not fileSearch.Success:
            raise Exception(fileSearch.Error)
        if len(fileSearch.Files) == 0:
            fileRegister = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=open(RUNOF_HOST_PATH, 'rb').read(),
                DeleteAfterFetch=False,
                Filename="COFFLoader.dll",
                IsScreenshot=False,
                IsDownloadFromAgent=False,
                Comment=f"Shared COFFLoader.dll for all execute_coff tasks within apollo"
            ))
            if fileRegister.Success:
                return fileRegister.AgentFileId
            raise Exception(fileRegister.Error)
        return fileSearch.Files[0].AgentFileId

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID, Success=True)
        originalGroupNameIsDefault = taskData.args.get_parameter_group_name() == "Default"
        if taskData.args.get_parameter_group_name() == "New":
            fileSearchResp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID,
                AgentFileID=taskData.args.get_arg("bof_file")
            ))
            if not fileSearchResp.Success:
                raise Exception(f"Failed to find uploaded file: {fileSearchResp.Error}")
            if len(fileSearchResp.Files) == 0:
                raise Exception(f"Failed to find matching file, was it deleted?")
            searchedTaskResp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
                TaskID=taskData.Task.ID,
                SearchCallbackID=taskData.Callback.ID,
                SearchCommandNames=["register_file"],
                SearchParams=taskData.args.get_arg("bof_file")
            ))
            if not searchedTaskResp.Success:
                raise Exception(f"Failed to search for matching tasks: {searchedTaskResp.Error}")
            if len(searchedTaskResp.Tasks) == 0:
                # we need to register this file with apollo first
                subtaskCreationResp = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="register_file",
                    Params=json.dumps({"file": taskData.args.get_arg("bof_file")})
                ))
                if not subtaskCreationResp.Success:
                    raise Exception(f"Failed to create register_file subtask: {subtaskCreationResp.Error}")

            taskData.args.add_arg("coff_name", fileSearchResp.Files[0].Filename)
            taskData.args.add_arg("bof_id", taskData.args.get_arg("bof_file"))
            taskData.args.remove_arg("bof_file")
        else:
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(TaskID=taskData.Task.ID, Filename=taskData.args.get_arg("coff_name")))
            if file_resp.Success and len(file_resp.Files) > 0:
                taskData.args.add_arg("bof_id", file_resp.Files[0].AgentFileId)
            else:
                raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("coff_name")))
        timeout = taskData.args.get_arg("timeout")
        if timeout is None:
            taskData.args.set_arg("timeout", 30)
        registered_runof_id = await self.registered_runof(taskData)
        taskData.args.add_arg("coff_id", registered_runof_id)
        taskargs = taskData.args.get_arg("coff_arguments")
        argsString = ""
        normalizedArgs = []
        packedArgsBuffer = b''
        packedArgsSize = 0
        for argEntry in taskargs:
            if argEntry[0] in ['s', 'int16']:
                argsString += f"-Arguments {argEntry[0]}:{argEntry[1]} "
                normalizedArgs.append(['s', argEntry[1]])
                packedArgsBuffer += struct.pack("<h", int(argEntry[1]))
                packedArgsSize += struct.calcsize("<h")
            elif argEntry[0] in ['i', 'int32']:
                argsString += f"-Arguments {argEntry[0]}:{argEntry[1]} "
                normalizedArgs.append(['i', argEntry[1]])
                packedArgsBuffer += struct.pack("<i", int(argEntry[1]))
                packedArgsSize += struct.calcsize("<i")
            elif argEntry[0] in ['z', 'string']:
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                normalizedArgs.append(['z', argEntry[1]])
                stringVal = (argEntry[1] + '\x00').encode("utf-8")
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)
            elif argEntry[0] in ['Z', 'wchar']:
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                normalizedArgs.append(['Z', argEntry[1]])
                stringVal = (argEntry[1] + '\x00').encode("utf-16_le")
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)
            else:
                argsString += f"-Arguments {argEntry[0]}:\"{argEntry[1]}\" "
                normalizedArgs.append(['b', argEntry[1]])
                stringVal = base64.b64decode(argEntry[1])
                packedFormat = f"<L{len(stringVal)}s"
                packedArgsBuffer += struct.pack(packedFormat, len(stringVal), stringVal)
                packedArgsSize += struct.calcsize(packedFormat)
        finalPackedArgs = binascii.hexlify(struct.pack("<L", packedArgsSize) + packedArgsBuffer).decode('utf-8')
        taskData.args.remove_arg("coff_arguments")
        taskData.args.add_arg("coff_arguments", finalPackedArgs, type=ParameterType.String,
                              parameter_group_info=[
                                  ParameterGroupInfo(
                                      required=False,
                                      group_name="Default",
                                      ui_position=4
                                  ),
                                  ParameterGroupInfo(
                                      required=False,
                                      group_name="New",
                                      ui_position=4
                                  ),
                              ])
        if originalGroupNameIsDefault:
            if taskargs == "" or taskargs is None:
                response.DisplayParams = "-Coff {} -Function {} -Timeout {}".format(
                    taskData.args.get_arg("coff_name"),
                    taskData.args.get_arg("function_name"),
                    taskData.args.get_arg("timeout")
                )
            else:
                response.DisplayParams = "-Coff {} -Function {} -Timeout {} {}".format(
                    taskData.args.get_arg("coff_name"),
                    taskData.args.get_arg("function_name"),
                    taskData.args.get_arg("timeout"),
                    argsString
                )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
