from mythic_payloadtype_container.MythicCommandBase import *
import json


class Spawntox64Arguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "application": CommandParameter(name="Path to Application", type=ParameterType.String, required=True, default_value="C:\\Windows\\System32\\rundll32.exe"),
            "arguments": CommandParameter(name="Arguments", type=ParameterType.String, default_value="", required=False)
        }

    def split_commandline(self):
        if self.command_line[0] == "{":
            raise Exception("split_commandline expected string, but got JSON object: " + self.command_line)
        inQuotes = False
        curCommand = ""
        cmds = []
        for x in range(len(self.command_line)):
            c = self.command_line[x]
            if c == '"' or c == "'":
                inQuotes = not inQuotes
            if (not inQuotes and c == ' '):
                cmds.append(curCommand)
                curCommand = ""
            else:
                curCommand += c
        
        if curCommand != "":
            cmds.append(curCommand)
        
        for x in range(len(cmds)):
            if cmds[x][0] == '"' and cmds[x][-1] == '"':
                cmds[x] = cmds[x][1:-1]
            elif cmds[x][0] == "'" and cmds[x][-1] == "'":
                cmds[x] = cmds[x][1:-1]

        return cmds

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("spawnto_x64 requires a path to an executable to be passed on the command line.\n\tUsage: {}".format(Spawntox64Command.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.split_commandline()
            self.add_arg("application", parts[0])
            firstIndex = self.command_line.index(parts[0])
            cmdline = self.command_line[firstIndex+len(parts[0]):].strip()
            if cmdline[0] in ['"', "'"]:
                cmdline = cmdline[1:].strip()
            self.add_arg("arguments", cmdline)

        pass


class Spawntox64Command(CommandBase):
    cmd = "spawnto_x64"
    needs_admin = False
    help_cmd = "spawnto_x64 [path] [args]"
    description = "Change the default binary used in post exploitation jobs to [path]. If [args] provided, the process is launched with those arguments."
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = Spawntox64Arguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        args = task.args.get_arg("arguments")
        task.display_params = task.args.get_arg("application")
        if args:
            task.display_params += " {}".format(args)
        return task

    async def process_response(self, response: AgentResponse):
        pass