from mythic_container.MythicCommandBase import *
import json


class CdArguments(TaskArguments):


    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Path to Directory",
                type=ParameterType.String,
                description="Directory to change to."),
        ]
    


    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require path to change directory to.\nUsage:\n\t{}".format(CdCommand.help_cmd))
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            if self.command_line[0] == '"' and self.command_line[-1] == '"':
                self.command_line = self.command_line[1:-1]
            elif self.command_line[0] == "'" and self.command_line[-1] == "'":
                self.command_line = self.command_line[1:-1]    
            self.add_arg("path", self.command_line)


class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd [path]"
    description = "Change directory to [path]. Path relative identifiers such as ../ are accepted."
    version = 2
    author = "@djhohnstein"
    argument_class = CdArguments
    attackmapping = ["T1083"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("path")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp