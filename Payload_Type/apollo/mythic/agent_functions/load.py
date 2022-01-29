import asyncio
import os
from distutils.dir_util import copy_tree
import tempfile
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
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


    async def get_remaining_commands(self, callback: dict):
        all_cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=callback["id"],
            loaded_only=False)
        loaded_cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=callback["id"],
            loaded_only=True)

        if all_cmds.status != MythicStatus.Success:
            raise Exception("Failed to get commands for apollo agent: {}".format(all_cmds.status))
        if loaded_cmds.status != MythicStatus.Success:
            raise Exception("Failed to fetch loaded commands from callback {}: {}".format(callback["id"], loaded_cmds.status))
        
        all_cmds_names = set([r["cmd"] for r in all_cmds.response])
        loaded_cmds_names = set([r["cmd"] for r in loaded_cmds.response])
        diff = all_cmds_names.difference(loaded_cmds_names)
        return sorted(diff)


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

    async def get_commands(self, callback: Callback, loaded_only: bool):
        cmds = await MythicRPC().execute(
            "get_commands",
            callback_id=callback.id,
            loaded_only=loaded_only)
        
        if cmds.status != MythicStatus.Success:
            raise Exception("Failed to get commands: {}".format(cmds.status))
        
        return cmds.response

    def mprint(self, thing):
        print(thing)
        sys.stdout.flush()

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dependency_required = []
        dependency_not_required = []
        script_only = []
        not_script_only = []
        load_map = {
            "depdency_required": {
                "dependency_not_loaded": {
                    # Each of these should be of the form:
                    # cmd_name: loaded_status_bool
                },
                "dependency_loaded": {

                }
            },
            "dependency_not_required": {
                "script_only": {

                },
                "not_script_only": {
                }
            }
        }
        requested_cmds = task.args.get_arg("commands")
            
        loaded_cmds = await self.get_commands(task.callback, True)
        all_cmds = await self.get_commands(task.callback, False)

        loaded_cmds_dict = {r["cmd"]: r for r in loaded_cmds}
        all_cmds_dict = {r["cmd"]: r for r in all_cmds}

        diff_cmds_dict = {k: all_cmds_dict[k] for k in all_cmds_dict.keys() if k not in loaded_cmds_dict.keys()}


        requested_cmd_objects = []
        for cmd_name, cmd in diff_cmds_dict.items():
            if cmd_name in requested_cmds:
                requested_cmd_objects.append(cmd)
        
        if len(requested_cmd_objects) == 0:
            raise Exception("No commands to load.")
        
        for cmd in requested_cmd_objects:
            if cmd["attributes"].get("dependencies", None) == None:
                if cmd["script_only"] == True:
                    script_only.append(cmd)
                else:
                    not_script_only.append(cmd)
            else:
                dep_list = cmd["attributes"].get("dependencies", None)
                dep_cmd_objects = []
                dep_cmd_notloaded = []
                num_deps = len(dep_list)
                found_deps = 0
                all_deps_loaded = False
                for loaded_cmd in loaded_cmds:
                    if loaded_cmd["cmd"] in dep_list:
                        found_deps += 1
                        dep_cmd_objects.append(loaded_cmd)
                        if found_deps == num_deps:
                            all_deps_loaded = True
                            break
                if all_deps_loaded:
                    dependency_not_required.append(cmd)
                else:
                    for all_cmd in all_cmds:
                        if all_cmd["cmd"] in dep_list:
                            found_deps += 1
                            dep_cmd_notloaded.append(all_cmd)
                            if found_deps == num_deps:
                                break
                    for dep_cmd in dep_cmd_notloaded:
                        dependency_required.append(dep_cmd)


        to_compile = set([x["cmd"] for x in dependency_required + not_script_only])

        to_load_via_rpc = set([x["cmd"] for x in dependency_not_required + script_only])

        if len(to_load_via_rpc) > 0:
            reg_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=task.id,
                commands=to_load_via_rpc,
                add=True)
            if reg_resp.status != MythicStatus.Success:
                raise Exception("Failed to register {} commands: {}".format(to_load_via_rpc, reg_resp.response))

        if len(to_compile) == 0:
            task.status = MythicStatus.Completed
        else:
            defines_commands_upper = [f"#define {x.upper()}" for x in to_compile]
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
        
        all_task_cmds = [x for x in to_compile.union(to_load_via_rpc)]
        task.display_params = "-Commands {}".format(" ".join(all_task_cmds))
        return task

    async def process_response(self, response: AgentResponse):
        resp = response.response["commands"]
        self.mprint("Parsing commands from process_response: {}".format(resp))


        reg_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=response.task.id,
                commands=resp,
                add=True)
        if reg_resp.status != MythicStatus.Success:
            raise Exception("Failed to register commands ({}) from response: {}".format(resp, reg_resp.response))

        all_cmds = await self.get_commands(response.callback, False)
        all_cmds_dict = {x["cmd"]: x for x in all_cmds}
        loaded_cmds = await self.get_commands(response.callback, True)
        loaded_cmds_dict = {x["cmd"]: x for x in loaded_cmds}
        loaded_cmd_names = [x["cmd"] for x in loaded_cmds]

        diff_cmds_dict = {k: v for k, v in all_cmds_dict.items() if k not in loaded_cmd_names}

        to_add = []

        if len(diff_cmds_dict.keys()) > 0:
            for cmd_name, cmd in diff_cmds_dict.items():
                if cmd["attributes"].get("dependencies", None) is not None:
                    deps = cmd["attributes"].get("dependencies", None)
                    found_deps = 0
                    for d in deps:
                        if d in loaded_cmd_names:
                            found_deps += 1
                            if found_deps == len(deps):
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
        addoutput_resp = await MythicRPC().execute("create_output",
                                                    task_id=response.task.id,
                                                    output="{}, ".format(", ".join(newly_loaded_cmds)))
        if addoutput_resp.status != MythicStatus.Success:
            raise Exception("Failed to add output to task")
        
