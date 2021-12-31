from mythic_payloadtype_container.MythicCommandBase import *
import json


class LsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                cli_name="Host",
                display_name="Host",
                type=ParameterType.String,
                description="Host to list files from.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Path to list files from.",
                type=ParameterType.String,
                description="Path to list files from.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=0
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            # We'll never enter this control flow
            if self.command_line[0] == '{':
                temp_json = json.loads(self.command_line)
                if "file" in temp_json.keys():
                    # we came from the file browser
                    host = ""
                    path = temp_json['path']
                    if 'file' in temp_json and temp_json['file'] != "":
                        path += "\\" + temp_json['file']
                    if 'host' in temp_json:
                        # this means we have tasking from the file browser rather than the popup UI
                        # the apfell agent doesn't currently have the ability to do _remote_ listings, so we ignore it
                        host = temp_json['host']

                    self.add_arg("host", host)
                    self.add_arg("path", path)
                    self.add_arg("file_browser", "true")
                else:
                    self.load_args_from_json_string(self.command_line)
            else:
                host = ""
                if self.command_line[0] == "\\" and self.command_line[1] == "\\":
                    final = self.command_line.find("\\", 2)
                    if final != -1:
                        host = self.command_line[2:final]
                self.add_arg("host", host)
                self.add_arg("path", self.command_line)
                self.add_arg("file_browser", "true")
        else:
            self.add_arg("host", "")
            self.add_arg("path", self.command_line)
            self.add_arg("file_browser", "true")
        if self.get_arg("path") is None:
            self.add_arg("path", ".")



class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List files and folders in a specified directory (defaults to your current working directory.)"
    version = 2
    is_exit = False
    supported_ui_features = ["file_browser:list"]
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = LsArguments
    attackmapping = ["T1106", "T1083"]
    browser_script = BrowserScript(script_name="ls_new", author="@djhohnstein", for_new_ui=True)

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        host = task.args.get_arg("host")
        path = task.args.get_arg("path")
        if host:
            task.display_params = "{} on {}".format(path, host)
        else:
            task.display_params = path
        return task

    async def process_response(self, response: AgentResponse):
        pass