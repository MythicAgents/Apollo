from mythic_payloadtype_container.MythicCommandBase import *
import json


class NetstatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="tcp",
                cli_name="Tcp",
                display_name="TCP",
                type=ParameterType.Boolean,
                default_value=False,
                description="Display only TCP entries.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False
                    ),
                ]),
            CommandParameter(
                name="udp",
                cli_name="Udp",
                display_name="UDP",
                type=ParameterType.Boolean,
                default_value=False,
                description="Display only UDP entries.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False
                    ),
                ]),
            CommandParameter(
                name="established",
                cli_name="Established",
                display_name="Established",
                type=ParameterType.Boolean,
                default_value=False,
                description="Display only established entries.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False
                    ),
                ]),
            CommandParameter(
                name="listen",
                cli_name="Listen",
                display_name="Listen",
                type=ParameterType.Boolean,
                default_value=False,
                description="Display only listening entries.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False
                    ),
                ]),
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

    errorMsg = "Missing required argument: {}"

    async def parse_arguments(self):
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Require JSON.")


class NetstatCommand(CommandBase):
    cmd = "netstat"
    needs_admin = False
    help_cmd = "netstat"
    description = "View netstat entries"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@thespicybyte"
    argument_class = NetstatArguments
    attackmapping = []
    supported_ui_features = []
    browser_script = BrowserScript(script_name="netstat", author="@thespicybyte", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass