import asyncio
import os
from distutils.dir_util import copy_tree
import tempfile
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import sys


class LoadArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="commands",
                cli_name="Commands",
                display_name="Commands", 
                type=ParameterType.ChooseMultiple,
                description="One or more commands to load into the agent", 
                dynamic_query_function=self.get_remaining_commands,),
        ]


    async def get_remaining_commands(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        all_cmds = await SendMythicRPCCommandSearch(MythicRPCCommandSearchMessage(
            SearchPayloadTypeName="apollo"
        ))
        loaded_cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=inputMsg.Callback,
            loaded_only=True)

        if not all_cmds.Success:
            raise Exception("Failed to get commands for apollo agent: {}".format(all_cmds.Error))
        if loaded_cmds.status != MythicStatus.Success:
            raise Exception("Failed to fetch loaded commands from callback {}: {}".format(inputMsg.Callback, loaded_cmds.status))
        
        all_cmds_names = set([r.Name for r in all_cmds.Commands])
        loaded_cmds_names = set([r["cmd"] for r in loaded_cmds.response])
        logger.info(all_cmds_names)
        logger.info(loaded_cmds_names)
        diff = all_cmds_names.difference(loaded_cmds_names)
        fileResponse.Success = True
        fileResponse.Choices = sorted(diff)
        return fileResponse


    async def parse_arguments(self):
        if self.command_line[0] == "{":
            tmpjson = json.loads(self.command_line)
            if tmpjson.get("Commands") is not None and type(tmpjson.get("Commands")) is not list:
                cmds = tmpjson.get("Commands").split(" ")
                tmpjson["Commands"] = cmds
                self.load_args_from_json_string(json.dumps(tmpjson)) 
            else:
                self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("No command line parsing available.")


class LoadCommand(CommandBase):
    cmd = "load"
    needs_admin = False
    help_cmd = "load [cmd1] [cmd2] [...]"
    description = 'Load one or more new commands into the agent.'
    version = 2
    author = "@djhohnstein"
    argument_class = LoadArguments
    attackmapping = []

    async def update_output(self, task: MythicTask, output: str):
        addoutput_resp = await MythicRPC().execute("create_output",
                                                    task_id=task.id,
                                                    output=output)
        if addoutput_resp.status != MythicStatus.Success:
            raise Exception("Failed to add output to task")


    async def create_tasking(self, task: MythicTask) -> MythicTask:
        requested_cmds = await SendMythicRPCCommandSearch(MythicRPCCommandSearchMessage(
            SearchPayloadTypeName="apollo",
            SearchCommandNames=task.args.get_arg("commands"),
        ))
        loaded_cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=task.callback.id,
            loaded_only=True)

        requested_cmds_names = set([r.Name for r in requested_cmds.Commands])
        loaded_cmds_names = set([r["cmd"] for r in loaded_cmds.response])
        diff = requested_cmds_names.difference(loaded_cmds_names)

        load_immediately_rpc = []
        to_compile = []

        # This is now the list of commands that need to be loaded
        requested_cmds = [r for r in requested_cmds.Commands if r.Name in diff]
        for requested_cmd in requested_cmds:
            dependencies = requested_cmd.Attributes.get("dependencies", [])
            script_only = requested_cmd.ScriptOnly
            if len(dependencies) == 0 and script_only:
                load_immediately_rpc.append(requested_cmd.Name)
            elif len(dependencies) > 0 and script_only:
                dep_not_loaded = [x for x in dependencies if x not in loaded_cmds_names]
                if len(dep_not_loaded) > 0:
                    to_compile += dep_not_loaded
                else:
                    load_immediately_rpc.append(requested_cmd.Name)
            elif len(dependencies) == 0 and not script_only:
                to_compile.append(requested_cmd.Name)
            elif len(dependencies) > 0 and not script_only:
                dep_not_loaded = [x for x in dependencies if x not in loaded_cmds_names]
                if len(dep_not_loaded) > 0:
                    to_compile += dep_not_loaded
                to_compile.append(requested_cmd.Name)
            else:
                raise Exception("Unreachable code path.")

        to_compile = set(to_compile)

        load_immediately_rpc = set(load_immediately_rpc)

        if len(load_immediately_rpc) > 0:
            reg_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=task.id,
                commands=list(load_immediately_rpc),
                add=True)
            if reg_resp.status != MythicStatus.Success:
                raise Exception("Failed to register {} commands: {}".format(load_immediately_rpc, reg_resp.response))

        if len(to_compile) == 0:
            await self.update_output(task, "Loaded {}\n".format(", ".join(load_immediately_rpc)))
            task.status = MythicStatus.Completed
        else:
            defines_commands_upper = [f"#define {x.upper()}" for x in to_compile]
            agent_build_path = tempfile.TemporaryDirectory()
                # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path.name)
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
            shell_cmd = "rm -rf packages/*; nuget restore -NoCache -Force; msbuild -p:Configuration=Release {}/Tasks/Tasks.csproj".format(agent_build_path.name)
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
                    task.args.remove_arg("commands")
                    task.args.add_arg("commands", list(to_compile), ParameterType.ChooseMultiple)
                else:
                    raise Exception("Failed to register task dll with Mythic")
            else:
                raise Exception("Failed to build task dll. Stdout/Stderr:\n{}\n\n{}".format(stdout, stderr))
        
        all_task_cmds = [x for x in to_compile.union(load_immediately_rpc)]
        task.display_params = "-Commands {}".format(" ".join(all_task_cmds))
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        result = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        resp = response["commands"]
        logger.info("process_response loaded data", response)

        reg_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=response.task.id,
                commands=resp,
                add=True)
        if reg_resp.status != MythicStatus.Success:
            raise Exception("Failed to register commands ({}) from response: {}".format(resp, reg_resp.response))

        all_cmds = await SendMythicRPCCommandSearch(MythicRPCCommandSearchMessage(
            SearchPayloadTypeName="apollo",
            SearchCommandNames=task.args.get_arg("commands"),
        ))
        loaded_cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=task.Task.CallbackID,
            loaded_only=True)
        all_cmds_dict = {x.Name: x for x in all_cmds.Commands}
        loaded_cmd_names = [x["cmd"] for x in loaded_cmds.response]

        diff_cmds_dict = {k: v for k, v in all_cmds_dict.items() if k not in loaded_cmd_names}

        to_add = []

        if len(diff_cmds_dict.keys()) > 0:
            for cmd_name, cmd in diff_cmds_dict.items():
                dependencies = cmd["attributes"].get("dependencies", [])
                if len(dependencies) > 0:
                    found_deps = 0
                    for d in dependencies:
                        if d in loaded_cmd_names:
                            found_deps += 1
                            if found_deps == len(dependencies):
                                to_add.append(cmd_name)
                                break
            if len(to_add) > 0:
                reg_resp = await MythicRPC().execute(
                    "update_loaded_commands",
                    task_id=response.task.id,
                    commands=to_add,
                    add=True)
                if reg_resp.status != MythicStatus.Success:
                    raise Exception("Failed to register commands ({}) from response: {}".format(to_add, reg_resp.response))

        newly_loaded_cmds = set(resp).union(set(to_add))
        await self.update_output(response.task, "Loaded {}\n".format(", ".join(newly_loaded_cmds)))
        return result
