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

    def mprint(self, thing):
        print(thing)
        sys.stdout.flush()

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        requested_cmds = task.args.get_arg("commands")
        cmd_resp = await MythicRPC().execute(
            "get_commands",
            callback_id=task.callback.id,
            loaded_only=False)
        if cmd_resp.status != MythicStatus.Success:
            raise Exception("Failed to get commands for agent: {}".format(cmd_resp.response))
        
        agent_cmds = []
        no_dep_cmds = []


        all_cmds = cmd_resp.response
        for requested_cmd in requested_cmds:
            found = False
            for all_cmd in all_cmds:
                if requested_cmd == all_cmd["cmd"]:
                    found = True
                    if all_cmd["attributes"].get("dependencies", None) != None:
                        if requested_cmd == "socks":
                            no_dep_cmds.append(requested_cmd)
                        else:
                            for dep in all_cmd["attributes"]["dependencies"]:
                                agent_cmds.append(dep)
                    else:
                        agent_cmds.append(requested_cmd)
            if not found:
                raise Exception("Command {} not found".format(requested_cmd))

        if len(no_dep_cmds) > 0:
            register_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=task.id,
                commands=no_dep_cmds,
                add=True)
            if register_resp.status != MythicStatus.Success:
                raise Exception("Failed to register commands {} for agent: {}".format(", ".join(no_dep_cmds), register_resp.response))
            else:
                addoutput_resp = await MythicRPC().execute(
                    "create_output",
                    task_id=task.id,
                    output="Loaded {}".format(", ".join(no_dep_cmds)))
                if addoutput_resp.status != MythicStatus.Success:
                    raise Exception("Failed to add output for agent, but registered commands: {}".format(", ".join(no_dep_cmds)))

        self.mprint("Loading commands: {}".format(agent_cmds))


        defines_commands_upper = [f"#define {x.upper()}" for x in agent_cmds]
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
                task.args.add_arg("commands", agent_cmds, ParameterType.ChooseMultiple)
            else:
                raise Exception("Failed to register task dll with Mythic")
        else:
            raise Exception("Failed to build task dll. Stdout/Stderr:\n{}\n\n{}".format(stdout, stderr))
        task.display_params = "-Commands {}".format(" ".join(task.args.get_arg("commands")))
        return task

    async def process_response(self, response: AgentResponse):
        resp = response.response["commands"]
        self.mprint("Parsing commands from process_response: {}".format(resp))
        cmd_resp = await MythicRPC().execute(
            "get_commands",
            callback_id=response.task.callback.id,
            loaded_only=False)
        if cmd_resp.status != MythicStatus.Success:
            raise Exception("Failed to get commands for agent: {}".format(cmd_resp.response))
        
        all_cmds = cmd_resp.response
        
        to_register = []
        self.mprint("Total number of commands: {}".format(len(all_cmds)))
        for all_cmd in all_cmds:
            self.mprint("Attributes for {}: {}".format(all_cmd["cmd"], all_cmd["attributes"]))
            if all_cmd["attributes"].get("dependencies", None) != None:
                add = True
                for dep in all_cmd["attributes"]["dependencies"]:
                    if dep not in resp:
                        self.mprint("{} not in response, skipping".format(dep))
                        add = False
                if add:
                    to_register.append(all_cmd["cmd"])
            else:
                self.mprint("No dependencies for {}".format(all_cmd["cmd"]))
        
        self.mprint("To register: {}".format(to_register))
        if len(to_register) > 0:
            reg_resp = await MythicRPC().execute(
                "update_loaded_commands",
                task_id=response.task.id,
                commands=to_register,
                add=True)
            if reg_resp.status != MythicStatus.Success:
                raise Exception("Failed to register dependent commands: {}".format(reg_resp.response))

            for i in range(to_register):
                to_register[i] = "{} (script only)".format(to_register[i])
            addoutput_resp = await MythicRPC().execute("create_output",
                                                    task_id=response.task.id,
                                                    output=", {}".format(", ".join(to_register)))
            if addoutput_resp.status != MythicStatus.Success:
                raise Exception("Failed to add output to task")
        
