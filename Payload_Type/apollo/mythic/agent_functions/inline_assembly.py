from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from agent_functions.execute_pe import PRINTSPOOFER_FILE_ID
from sRDI import ShellcodeRDI
from mythic_payloadtype_container.MythicRPC import *
from os import path
import base64
import tempfile
from distutils.dir_util import copy_tree
import shutil

INTEROP_ASSEMBLY_PATH = "/srv/ApolloInterop.dll"
INTEROP_FILE_ID = ""

class InlineAssemblyArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly_name",
                cli_name = "Assembly",
                display_name = "Assembly",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Assembly to execute (e.g., Seatbelt.exe).",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
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
                        group_name="Default",
                        ui_position=2
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

    async def get_files(self, callback: dict):
        file_resp = await MythicRPC().execute("get_file", callback_id=callback["id"],
                                              limit_by_callback=True,
                                              get_contents=False,
                                              filename="",
                                              max_results=-1)
        if file_resp.status == MythicRPCStatus.Success:
            file_names = []
            for f in file_resp.response:
                if f["filename"] not in file_names and f["filename"].endswith(".exe"):
                    file_names.append(f["filename"])
            return file_names
        else:
            return []


class InlineAssemblyCommand(CommandBase):
    cmd = "inline_assembly"
    needs_admin = False
    help_cmd = "inline_assembly [Assembly.exe] [args]"
    description = "Executes a .NET assembly with the specified arguments in a disposable AppDomain. This assembly must first be known by the agent using the `register_assembly` command."
    version = 3
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@thiagomayllart"
    argument_class = InlineAssemblyArguments
    attackmapping = ["T1547"]

    async def build_interop(self):
        global INTEROP_ASSEMBLY_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/ApolloInterop/bin/Release/ApolloInterop.dll".format(agent_build_path.name)
        copy_tree(self.agent_code_path, agent_build_path.name)
        shell_cmd = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release {}/ApolloInterop/ApolloInterop.csproj".format(agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build ApolloInterop.dll:\n{}".format(stderr.decode()))
        shutil.copy(outputPath, INTEROP_ASSEMBLY_PATH)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        global INTEROP_ASSEMBLY_PATH
        global INTEROP_FILE_ID

        if not path.exists(INTEROP_ASSEMBLY_PATH):
            await self.build_interop()

        if INTEROP_FILE_ID == "":
            with open(INTEROP_ASSEMBLY_PATH, "rb") as f:
                interop_bytes = f.read()
            b64interop = base64.b64encode(interop_bytes).decode()
            file_resp = await MythicRPC().execute(
                "create_file",
                task_id=task.id,
                file=b64interop,
                delete_after_fetch=False)
            
            if file_resp.status == MythicStatus.Success:
                INTEROP_FILE_ID = file_resp.response["agent_file_id"]
            else:
                raise Exception("Failed to register Interop DLL: {}".format(file_resp.error))
        
        task.args.add_arg("interop_id", INTEROP_FILE_ID)

        task.display_params = "-Assembly {} -Arguments {}".format(
            task.args.get_arg("assembly_name"),
            task.args.get_arg("assembly_arguments")
        )

        return task

    async def process_response(self, response: AgentResponse):
        pass