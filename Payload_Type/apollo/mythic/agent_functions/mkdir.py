from mythic_payloadtype_container.MythicCommandBase import *
import json


class MkdirArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Path",
                type=ParameterType.String, 
                description="Directory to create."),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No path given.\n\tUsage: {}".format(MkdirCommand.help_cmd))
        if self.command_line[0] == '"' and self.command_line[-1] == '"':
            self.command_line = self.command_line[1:-1]
        elif self.command_line[0] == "'" and self.command_line[-1] == "'":
            self.command_line = self.command_line[1:-1]
        
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line)

        pass


class MkdirCommand(CommandBase):
    cmd = "mkdir"
    needs_admin = False
    help_cmd = "mkdir [path]"
    description = "Make a directory specified by [path]"
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@djhohnstein"
    argument_class = MkdirArguments
    attackmapping = ["T1106"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "-Path {}".format(task.args.get_arg("path"))
        return task

    async def process_response(self, response: AgentResponse):
        pass