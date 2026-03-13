from mythic_container.MythicCommandBase import *
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
                name="modify",
                cli_name="Modify",
                display_name="Modify",
                type=ParameterType.Boolean,
                default_value=False,
                description="Modify service configuration",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Modify"
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
                display_name="Run As User",
                type=ParameterType.String,
                description="Account to run the service as (domain\\user or builtin)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Modify"
                    ),
                ]),
            CommandParameter(
                name="password",
                cli_name="Password",
                display_name="Run As Password",
                type=ParameterType.String,
                description="Password for the Run As account",
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
                type=ParameterType.String,
                description="ServiceType (e.g., SERVICE_NO_CHANGE, SERVICE_WIN32_OWN_PROCESS)",
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
                type=ParameterType.String,
                description="StartType (e.g., SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_AUTO_START)",
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
                description="List of dependency service names. Use [\"\"] to clear.",
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
                description="Service description",
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
    version = 4
    author = "@djhohnstein"
    argument_class = ScArguments
    attackmapping = ["T1106"]
    supported_ui_features = ["sc:start", "sc:stop", "sc:delete", "sc:modify"]
    browser_script = BrowserScript(script_name="sc", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        computer = taskData.args.get_arg("computer")
        service_name = taskData.args.get_arg("service")
        display_name = taskData.args.get_arg("display_name")
        binpath = taskData.args.get_arg("binpath")
        
        
        query = taskData.args.get_arg("query")
        if query:
            response.DisplayParams = "-Query"
        modify = taskData.args.get_arg("modify")
        if modify:
            response.DisplayParams = "-Modify"
        start = taskData.args.get_arg("start")
        if start:
            response.DisplayParams = "-Start"
        stop = taskData.args.get_arg("stop")
        if stop:
            response.DisplayParams = "-Stop"
        create = taskData.args.get_arg("create")
        if create:
            response.DisplayParams = "-Create"
        delete = taskData.args.get_arg("delete")
        if delete:
            response.DisplayParams = "-Delete"

        if not any([query, modify, start, stop, create, delete]):
            raise Exception("Failed to get a valid action to perform.")
        if computer is not None and computer != "":
            response.DisplayParams += " -Computer {}".format(computer)

        if service_name is not None and service_name != "":
            response.DisplayParams += " -Service {}".format(service_name)

        if display_name is not None and display_name != "":
            response.DisplayParams += " -DisplayName '{}'".format(display_name)

        if binpath is not None and binpath != "":
            response.DisplayParams += " -BinPath '{}'".format(binpath)

        # Modify-only extras for better operator visibility
        if modify:
            service_type = taskData.args.get_arg("service_type")
            if service_type is not None and service_type != "":
                response.DisplayParams += " -ServiceType {}".format(service_type)

            start_type = taskData.args.get_arg("start_type")
            if start_type is not None and start_type != "":
                response.DisplayParams += " -StartType {}".format(start_type)

            run_as = taskData.args.get_arg("run_as")
            if run_as is not None and run_as != "":
                response.DisplayParams += " -RunAs '{}'".format(run_as)

            password = taskData.args.get_arg("password")
            if password is not None and password != "":
                response.DisplayParams += " -Password '{}'".format(password)

            dependencies = taskData.args.get_arg("dependencies")
            if dependencies is not None and dependencies != "":
                try:
                    if isinstance(dependencies, list):
                        deps_str = ",".join(dependencies)
                    else:
                        deps_str = str(dependencies)
                    response.DisplayParams += " -Dependencies [{}]".format(deps_str)
                except Exception:
                    pass

            description = taskData.args.get_arg("description")
            if description is not None and description != "":
                response.DisplayParams += " -Description '{}'".format(description)

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

