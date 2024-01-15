from distutils.dir_util import copy_tree
from mythic_container.MythicCommandBase import *
from uuid import uuid4
from mythic_container.MythicRPC import *
from os import path

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
                description="Entry function name.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=2
                    ),
                ]),
            CommandParameter(
                name="timeout",
                cli_name="Timeout",
                display_name="Timeout",
                type=ParameterType.String,
                description="Set thread timeout (in seconds).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=3
                    ),
                ]),
            CommandParameter(
                name="coff_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.Array,
                default_value=[],
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
        coff_arguments = []
        for argument in arguments.InputArray:
            type,value = argument.split(":")
            value = value.strip("\'").strip("\"")
            if type == "":
                pass
            elif type == "int16" or type == "-s":
                coff_arguments.append(["int16",int(value)])
            elif type == "int32" or type == "-i":
                coff_arguments.append(["int32",int(value)])
            elif type == "string" or type == "-z":
                coff_arguments.append(["string",value])
            elif type == "wchar" or type == "-Z":
                coff_arguments.append(["wchar",value])
            elif type == "base64" or type == "-b":
                coff_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False, Error=f"Failed to parse argument: {argument}: Unknown value type.")
        
        argumentResponse.Choices = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=coff_arguments)
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

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=taskData.Task.ID,
            Filename=taskData.args.get_arg("coff_name")
        ))
        if file_resp.Success and len(file_resp.Files) > 0:
            taskData.args.add_arg("loader_stub_id", file_resp.Files[0].AgentFileId)
        else:
            raise Exception("Failed to fetch uploaded file from Mythic (ID: {})".format(taskData.args.get_arg("coff_name")))

        timeout = taskData.args.get_arg("timeout")
        if timeout is None or timeout != "":
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
                taskData.args.get_arg("coff_arguments")
            )

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
