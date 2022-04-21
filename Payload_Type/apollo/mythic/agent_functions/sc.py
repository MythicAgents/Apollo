from mythic_payloadtype_container.MythicCommandBase import *
import json


class ScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="query",
                cli_name="Query",
                display_name="Query",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Query for services",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Query"
                    ),
            ]),
            CommandParameter(
                name="start",
                cli_name="Start",
                display_name="Start",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Start"
                    ),
            ]),
            CommandParameter(
                name="stop",
                cli_name="Stop",
                display_name="Stop",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Stop"
                    ),
            ]),
            CommandParameter(
                name="create",
                cli_name="Create",
                display_name="Create",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Create"
                    ),
            ]),
            CommandParameter(
                name="delete",
                cli_name="Delete",
                display_name="Delete",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Delete"
                    ),
            ]),
            CommandParameter(
                name="modify",
                cli_name="Modify",
                display_name="Modify",
                type=ParameterType.Boolean, 
                default_value=False, 
                description="Service controller action to perform.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Modify"
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
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
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
                    ParameterGroupInfo(
                        required=True,
                        group_name="Modify"
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
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
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
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="run_as",
                cli_name="RunAs",
                display_name="Run As",
                type=ParameterType.String,
                description="Specify the user the service will run as.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="password",
                cli_name="Password",
                display_name="Password",
                type=ParameterType.String,
                description="Plaintext password for service.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="service_type",
                cli_name="ServiceType",
                display_name="Service Type",
                type=ParameterType.ChooseOne,
                choices= [
                    "SERVICE_NO_CHANGE",
                    "SERVICE_KERNEL_DRIVER",
                    "SERVICE_FILE_SYSTEM_DRIVER",
                    "SERVICE_WIN32_OWN_PROCESS",
                    "SERVICE_WIN32_SHARE_PROCESS",
                    "SERVICE_INTERACTIVE_PROCESS",
                    "SERVICE_WIN32",
                ],
                default_value="SERVICE_NO_CHANGE",
                description="Set the service type.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="start_type",
                cli_name="StartType",
                display_name="Start Type",
                type=ParameterType.ChooseOne,
                choices= [
                    "SERVICE_NO_CHANGE",
                    "SERVICE_AUTO_START",
                    "SERVICE_BOOT_START",
                    "SERVICE_DEMAND_START",
                    "SERVICE_DISABLED",
                    "SERVICE_SYSTEM_START"
                ],
                default_value="SERVICE_NO_CHANGE",
                description="Set the service start type.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="dependencies",
                cli_name="Dependencies",
                display_name="Dependencies",
                type=ParameterType.Array,
                description="Set a list of dependencies.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="description",
                cli_name="Description",
                display_name="Description",
                type=ParameterType.String,
                description="Set the description of a service.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
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
    version = 3
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = ScArguments
    attackmapping = ["T1106"]
    supported_ui_features = ["sc:start", "sc:stop", "sc:delete", "sc:modify"]
    browser_script = BrowserScript(script_name="sc", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        computer = task.args.get_arg("computer")
        service_name = task.args.get_arg("service")
        display_name = task.args.get_arg("display_name")
        binpath = task.args.get_arg("binpath")
        run_as = task.args.get_arg("run_as")
        password = task.args.get_arg("password")
        service_type = task.args.get_arg("service_type")
        start_type = task.args.get_arg("start_type")
        dependencies = task.args.get_arg("dependencies")
        description = task.args.get_arg("description")
        
        query = task.args.get_arg("query")
        if query:
            task.display_params = "-Query"
        start = task.args.get_arg("start")
        if start:
            task.display_params = "-Start"
        stop = task.args.get_arg("stop")
        if stop:
            task.display_params = "-Stop"
        create = task.args.get_arg("create")
        if create:
            task.display_params = "-Create"
        delete = task.args.get_arg("delete")
        if delete:
            task.display_params = "-Delete"
        modify = task.args.get_arg("modify")
        if modify:
            task.display_params = "-Modify"

        if not any([query, start, stop, create, delete, modify]):
            raise Exception("Failed to get a valid action to perform.")
        if computer is not None and computer is not "":
            task.display_params += " -Computer {}".format(computer)

        if service_name is not None and service_name is not "":
            task.display_params += " -Service {}".format(service_name)

        if display_name is not None and display_name is not "":
            task.display_params += " -DisplayName '{}'".format(display_name)

        if binpath is not None and binpath is not "":
            task.display_params += " -BinPath '{}'".format(binpath)

        if run_as is not None and run_as is not "":
            task.display_params += " -RunAs '{}'".format(run_as)

        if password is not None and password is not "":
            task.display_params += " -Password '{}'".format(password)

        if modify:
            task.display_params += " -ServiceType '{}'".format(service_type)
            task.display_params += " -StartType '{}'".format(start_type)

        if dependencies is not None and not dependencies:
            task.display_params += " -Dependencies '{}'".format(",".join(dependencies))

        if description is not None and description is not "":
            task.display_params += " -Description '{}'".format(description)

        return task

    async def process_response(self, response: AgentResponse):
        pass
