from mythic_payloadtype_container.MythicCommandBase import *
import json


class RmArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Directory of File",
                type=ParameterType.String,
                description="The full path of the file to remove on the specified host"),
            CommandParameter(
                name="file",
                cli_name="File", 
                display_name="File",
                type=ParameterType.String, description="The file to remove on the specified host (used by file browser)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
            CommandParameter(
                name="host",
                cli_name="Host",
                display_name="Host",
                type=ParameterType.String,
                description="Computer from which to remove the file.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                host = ""
                if self.command_line[0] == "\\" and self.command_line[1] == "\\":
                    final = self.command_line.find("\\", 2)
                    if final != -1:
                        host = self.command_line[2:final]
                    else:
                        raise Exception("Invalid UNC path: {}".format(self.command_line))
                self.add_arg("host", host)
                self.add_arg("path", self.command_line)
        else:
            raise Exception("rm requires a path to remove.\n\tUsage: {}".format(RmCommand.help_cmd))



class RmCommand(CommandBase):
    cmd = "rm"
    needs_admin = False
    help_cmd = "rm [path]"
    description = "Delete a file specified by [path]"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    supported_ui_features = ["file_browser:remove"]
    author = "@djhohnstein"
    argument_class = RmArguments
    attackmapping = ["T1070.004", "T1565"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        host = task.args.get_arg("host")
        task.display_params = "-Path {}".format(task.args.get_arg("path"))
        if host:
            task.display_params += " -Host {}".format(host)
        return task

    async def process_response(self, response: AgentResponse):
        pass