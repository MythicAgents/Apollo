from CommandBase import *
import json


class NetLocalgroupMemberArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "computer": CommandParameter(name="computer", required=False, type=ParameterType.String, description="Computer to enumerate."),
            "group": CommandParameter(name="group", type=ParameterType.String, description="Group to enumerate.")
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
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            cmds = self.split_commandline()
            if len(cmds) == 1:
                self.add_arg("group", cmds[0])
            elif len(cmds) == 2:
                self.add_arg("computer", cmds[0])
                self.add_arg("group", cmds[1])
            else:
                raise Exception("Expected one or two arguments, but got: {}\n\tUsage: {}".format(cmds, NetLocalgroupMemberCommand.help_cmd))

class NetLocalgroupMemberCommand(CommandBase):
    cmd = "net_localgroup_member"
    needs_admin = False
    help_cmd = "net_localgroup_member [computer] [group]"
    description = "Retrieve local group membership of the group specified by [group]. If [computer] is omitted, defaults to localhost."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = NetLocalgroupMemberArguments
    attackmapping = []
    browser_script = BrowserScript(script_name="net_localgroup_member", author="@djhohnstein")

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass