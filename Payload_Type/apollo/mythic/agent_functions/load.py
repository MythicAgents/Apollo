import asyncio
import os
from distutils.dir_util import copy_tree
import tempfile
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json


class LoadArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "commands" : CommandParameter(name="Commands", 
                 type=ParameterType.ChooseMultiple, 
                 description="One or more commands to send to the agent", 
                 choices_are_all_commands=True),
        }

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            cmds = self.command_line.split(" ")
            self.args["commands"].value = cmds
        pass


class LoadCommand(CommandBase):
    cmd = "load"
    needs_admin = False
    help_cmd = "load [cmd1] [cmd2] [...]"
    description = 'Load one or more new commands into the agent.'
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = LoadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        defines_commands_upper = [f"#define {x.upper()}" for x in task.args.get_arg("commands")]
        agent_build_path = tempfile.TemporaryDirectory()
            # shutil to copy payload files over
        copy_tree(self.agent_code_path, agent_build_path.name)
        results = []
        for root, dirs, files in os.walk("{}/Tasks".format(agent_build_path.name)):
            for file in files:
                if file.endswith(".cs"):
                    results.append(os.path.join(root, file))
        if len(results) == 0:
            raise ValueError("No .cs files found in task library")
        for csFile in results:
            templateFile = open(csFile, "rb").read().decode()
            templateFile = templateFile.replace("#define COMMAND_NAME_UPPER", "\n".join(defines_commands_upper))
            if csFile.endswith(".cs"):
                with open(csFile, "a") as f:
                    f.write("\n")
                    f.write("\n".join(defines_commands_upper))
            with open(csFile, "wb") as f:
                f.write(templateFile.encode())
        
        outputPath = "{}/Tasks/bin/Release/Tasks.dll".format(agent_build_path.name)
        shell_cmd = "msbuild -p:Configuration=Release {}/Tasks/Tasks.csproj".format(agent_build_path.name)
        proc = await asyncio.create_subprocess_shell(shell_cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE, cwd=agent_build_path.name)
        stdout, stderr = await proc.communicate()
        if os.path.exists(outputPath):
            dllBytes = open(outputPath, "rb").read()
            file_resp = await MythicRPC().execute("create_file",
                                                  task_id=task.id,
                                                  file=base64.b64encode(dllBytes).decode(),
                                                  delete_after_fetch=True)
            if file_resp.status == MythicStatus.Success:
                task.args.add_arg("file_id", file_resp.response['agent_file_id'])
            else:
                raise Exception("Failed to register task dll with Mythic")
        else:
            raise Exception("Failed to build task dll. Stdout/Stderr:\n{}\n\n{}".format(stdout, stderr))
        return task

    async def process_response(self, response: AgentResponse):
        pass
