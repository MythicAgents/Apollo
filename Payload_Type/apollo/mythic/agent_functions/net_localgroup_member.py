from mythic_payloadtype_container.MythicCommandBase import *
import json


class NetLocalgroupMemberArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="computer",
                cli_name="Computer",
                display_name="Computer",
                type=ParameterType.String,
                description="Computer to enumerate.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
            CommandParameter(
                name="group",
                cli_name="Group",
                display_name="Group",
                type=ParameterType.String,
                description="Group to enumerate.")
        ]

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
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = NetLocalgroupMemberArguments
    attackmapping = ["T1590", "T1069"]
    browser_script = BrowserScript(script_name="net_localgroup_member_new", author="@djhohnstein", for_new_ui=True)
    supported_ui_features = ["net_localgroup_member"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        computer = task.args.get_arg("computer")
        group = task.args.get_arg("group")
        if computer:
            task.display_params = "-Computer {} -Group {}".format(computer, group)
        else:
            task.display_params = "-Group {}".format(group)
        return task

    async def process_response(self, response: AgentResponse):
        pass