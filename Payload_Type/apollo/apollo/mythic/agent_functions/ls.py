from mythic_container.MythicCommandBase import *
import re
import string


class LsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to list files from.",
                type=ParameterType.String,
                description="Path to list files from.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=1
                    ),
                ],
            ),
        ]

    async def parse_dictionary(self, dictionary_arguments):
        logger.info(dictionary_arguments)
        logger.info(self.tasking_location)
        self.load_args_from_dictionary(dictionary_arguments)
        if "host" in dictionary_arguments:
            if "full_path" in dictionary_arguments:
                self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["full_path"]}')
            elif "path" in dictionary_arguments:
                self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["path"]}')
            elif "file" in dictionary_arguments:
                self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["file"]}')
            else:
                logger.info("unknown dictionary args")
        else:
            if "path" not in dictionary_arguments or dictionary_arguments["path"] is None:
                self.add_arg("path", f'.')

    async def parse_arguments(self):
        # Check if named parameters were defined
        cli_names = [arg.cli_name for arg in self.args if arg.cli_name is not None]
        if (
            any([self.raw_command_line.startswith(f"-{cli_name} ") for cli_name in cli_names])
            or any([f" -{cli_name} " in self.raw_command_line for cli_name in cli_names])
        ):
            args = json.loads(self.command_line)
        # Freeform unmatched arguments
        else:
            args = {"path": "."}
            if len(self.raw_command_line) > 0:
                args["path"] = self.raw_command_line
        self.load_args_from_dictionary(args)


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List files and folders in a specified directory (defaults to your current working directory.)"
    version = 3
    supported_ui_features = ["file_browser:list"]
    author = "@djhohnstein"
    argument_class = LsArguments
    attackmapping = ["T1106", "T1083"]
    browser_script = BrowserScript(
        script_name="ls_new", author="@djhohnstein", for_new_ui=True
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        path = taskData.args.get_arg("path")
        response.DisplayParams = path

        if uncmatch := re.match(
            r"^\\\\(?P<host>[^\\]+)\\(?P<path>.*)$",
            path,
        ):
            taskData.args.add_arg("host", uncmatch.group("host"))
            taskData.args.set_arg("path", uncmatch.group("path"))
        else:
            # Set the host argument to an empty string if it does not exist
            taskData.args.add_arg("host", "")
        if host := taskData.args.get_arg("host"):
            host = host.upper()

            # Resolve 'localhost' and '127.0.0.1' aliases
            if host == "127.0.0.1" or host.lower() == "localhost":
                host = taskData.Callback.Host

            taskData.args.set_arg("host", host)

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
