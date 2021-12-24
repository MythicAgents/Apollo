from mythic_payloadtype_container.MythicCommandBase import *
import json


class ScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne, 
                choices=["query", "start", "stop", "create", "delete"], 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Query"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Start"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Stop"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Create"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Delete"
                    ),
                ]),
            CommandParameter(
                name="computer",
                cli_name="Computer",
                display_name="Computer",
                type=ParameterType.String,
                description="Host to perform the service action on.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="Query"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="Start"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="Stop"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="Create"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="Delete"
                    ),
                ]),
            CommandParameter(
                name="service",
                cli_name="ServiceName",
                display_name="Service Name",
                type=ParameterType.String,
                description="The name of the service.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Query"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Start"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Stop"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Create"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Delete"
                    ),
                ]),
            CommandParameter(
                name="display_name",
                cli_name="DisplayName",
                display_name="Display Name of Service",
                type=ParameterType.String,
                description="The display name of the service",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Query"
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="Create"
                    ),
                ]),
            CommandParameter(
                name="binpath",
                cli_name="BinPath",
                display_name="Binary Path",
                type=ParameterType.String,
                description="Path to the binary used in the create action.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Create"
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

class ScCommand(CommandBase):
    cmd = "sc"
    needs_admin = False
    help_cmd = "sc"
    description = "Service control manager wrapper function"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ScArguments
    attackmapping = ["T1106"]
    supported_ui_features = ["sc:start", "sc:stop", "sc:delete"]
    browser_script = BrowserScript(script_name="sc", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        action = task.args.get_arg("action")
        computer = task.args.get_arg("computer")
        service_name = task.args.get_arg("service")
        display_name = task.args.get_arg("display_name")
        binpath = task.args.get_arg("binpath")
        

        task.display_params = "-Action {}".format(action)
        if computer is not None and computer is not "":
            task.display_params += " -Computer {}".format(computer)

        if service_name is not None and service_name is not "":
            task.display_params += " -Service {}".format(service_name)

        if display_name is not None and display_name is not "":
            task.display_params += " -DisplayName '{}'".format(display_name)

        if binpath is not None and binpath is not "":
            task.display_params += " -BinPath '{}'".format(binpath)

        return task

    async def process_response(self, response: AgentResponse):
        pass